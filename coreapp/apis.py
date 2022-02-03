import json

from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, get_user_model
from rest_framework import exceptions
from django.utils.translation import ugettext_lazy as _
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response

from django.http import JsonResponse
from coreapp.models import Customer, Order, OrderDetails, Restaurant, Meal
from coreapp.serializers import RestaurantSerializer,  MealSerializer, OrderSerializer, \
  OrderStatusSerializer, CustomerAuthUserSerializer, OrderDriverSerializer

from django.utils import timezone
from oauth2_provider.models import AccessToken
from django.views.decorators.csrf import csrf_exempt

import stripe
from eatsbrendon.settings import STRIPE_API_KEY
stripe.api_key = STRIPE_API_KEY

class HelloView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)

class WrongArguments(exceptions.APIException):
    status_code = 400
    default_detail = _("Wrong Arguments")

    def __init__(self, detail=None):
        self.detail = detail or self.default_detail


def get_and_authenticate_user(username, password):
    user = authenticate(username=username, password=password)
    if user is None:
        raise WrongArguments("Invalid username/password. Please try again!")

    return user

def get_customer_from_user(user):
    try:
        customer = Customer.objects.get(user=user)
    except Customer.DoesNotExist:
        raise WrongArguments("No valid customer exists")
    return customer


class CustomerAuthViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = CustomerAuthUserSerializer

    @action(methods=["POST"], detail=False)
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # authenticate the user
        user = get_and_authenticate_user(**serializer.validated_data)
        customer = get_customer_from_user(user=user)
        token, created = Token.objects.get_or_create(user=user)

        return JsonResponse({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })

    @action(methods=["GET"], detail=False)
    def logout(self, request, format=None):
        # simply delete the token to force a login
        User = get_user_model()
        try:
            request.user.auth_token.delete()
        except User.auth_token.RelatedObjectDoesNotExist:
            return JsonResponse({"error": "No auth token found"})

        return JsonResponse({"success": True})

# ========
# RESTAURANT
# ========

def restaurant_order_notification(request, last_request_time):
  notification = Order.objects.filter(
    restaurant = request.user.restaurant, 
    created_at__gt = last_request_time
  ).count()

  return JsonResponse({"notification": notification})

# ========
# CUSTOMER
# ========
def customer_get_restaurants(request):
  restaurants = RestaurantSerializer(
    Restaurant.objects.all().order_by("-id"),
    many=True,
    context={"request": request}
  ).data
  return JsonResponse({"restaurants": restaurants})

def customer_get_meals(request, restaurant_id):
  meals = MealSerializer(
    Meal.objects.filter(restaurant_id=restaurant_id).order_by("-id"),
    many=True,
    context={"request": request}
  ).data
  return JsonResponse({"meals": meals})

@csrf_exempt
def customer_add_order(request):
  """
    params:
      1. access_token
      2. restaurant_id
      3. address
      4. order_details (json format), example:
          [{"meal_id": 2, "quantity":2}, {"meal_id": 3, "quantity": 3}]
    return:
      {"status": "success"}
  """

  data = json.loads(request.body)
  if request.method == "POST":
    # Get access token
    access_token = AccessToken.objects.get(
      token=data.get("access_token"),
      expires__gt = timezone.now()
    )

    # Get customer profile
    customer = access_token.user.customer

    # Check whether customer has any outstanding order
    if Order.objects.filter(customer=customer).exclude(status=Order.DELIVERED):
      return JsonResponse({"status": "failed", "error": "Your last order must be completed."})

    # Check order's address
    if not data.get("address"):
      return JsonResponse({"status": "failed", "error": "Address is required"})

    # Get order details
    order_details = json.loads(data.get("order_details"))

    # Check if meals in only one restaurant and then calculate the order total
    order_total = 0
    print(data)
    for meal in order_details:
      print(meal)
      if not Meal.objects.filter(id=meal["meal_id"], restaurant_id=int(data.get("restaurant_id"))):
        return JsonResponse({"status": "failed", "error": "Meals must be in only one restaurant"})
      else:
        order_total += Meal.objects.get(id=meal["meal_id"]).price * meal["quantity"] 

    # CREATE ORDER
    print(data)
    if len(order_details) > 0:

      # Step 1 - Create an Order
      order = Order.objects.create(
        customer = customer,
        restaurant_id = data.get("restaurant_id"),
        total = order_total,
        status = Order.COOKING,
        address = data.get("address")
      )

      # Step 2 - Create Order Details
      for meal in order_details:
        OrderDetails.objects.create(
          order = order,
          meal_id = meal["meal_id"],
          quantity = meal["quantity"],
          sub_total = Meal.objects.get(id=meal["meal_id"]).price * meal["quantity"]
        )

      return JsonResponse({"status": "success"})

  return JsonResponse({})

def customer_get_latest_order(request):
  """
    params:
      1. access_token
    return:
      {JSON data with all details of an order}
  """

  print(request.GET)
  access_token = AccessToken.objects.get(
    token=request.GET.get("access_token"),
    expires__gt = timezone.now()
  )
  customer = access_token.user.customer

  order = OrderSerializer(
    Order.objects.filter(customer=customer).last()
  ).data

  return JsonResponse({
    "last_order": order
  })

def customer_get_latest_order_status(request):
  """
    params:
      1. access_token
    return:
      {JSON data with all details of an order}
  """

  access_token = AccessToken.objects.get(
    token=request.GET.get("access_token"),
    expires__gt = timezone.now()
  )
  customer = access_token.user.customer

  order_status = OrderStatusSerializer(
    Order.objects.filter(customer=customer).last()
  ).data

  return JsonResponse({
    "last_order_status": order_status
  })

def customer_get_driver_location(request):
  access_token = AccessToken.objects.get(
    token=request.GET.get("access_token"),
    expires__gt = timezone.now()
  )

  customer = access_token.user.customer

  current_order = Order.objects.filter(customer = customer, status = Order.ONTHEWAY).last()
  if current_order:
    location = current_order.driver.location
  else:
    location = None

  return JsonResponse({
    "location": location
  })

@csrf_exempt
def create_payment_intent(request):

  """
    params:
      1. access_token
      2. total
    return:
      {"client_secret": client_secret}
  """


  data = json.loads(request.body)
  access_token = AccessToken.objects.get(
    token=data.get('access_token'),
    expires__gt = timezone.now()
  )

  # Get the order's total amount
  total = data.get('total')

  if request.method == "POST":
    print(' Is it POST yet?')
    if access_token:
      # Create a Payment Intent: this will create a client secret and return it to Mobile app
      try:
        intent = stripe.PaymentIntent.create(
          amount = int(float(total)) * 100, # Amount in cents
          currency = 'sgd',
          description = "Eatsbrendon Order"
        )

        print(intent)

        if intent:
          client_secret = intent.client_secret
          return JsonResponse({"client_secret": client_secret})

      except stripe.error.StripeError as e:
        return JsonResponse({"status": "failed", "error": str(e)})
      except Exception as e:
        return JsonResponse({"status": "failed", "error": str(e)})

    return JsonResponse({"status": "failed", "error": "Failed to create Payment Intent"})

# ========
# DRIVER
# ========

def driver_get_ready_orders(request):
  orders = OrderSerializer(
    Order.objects.filter(status = Order.READY, driver = None).order_by("-id"),
    many = True
  ).data

  return JsonResponse({
    "orders": orders
  })

@csrf_exempt
def driver_pick_order(request):
  """
    params:
      1. access_token
      2. order_id
    return:
      {"status": "success"}
  """

  if request.method == "POST":
    # Get access token
    access_token = AccessToken.objects.get(
      token=request.POST.get("access_token"),
      expires__gt = timezone.now()
    )

    # Get driver
    driver = access_token.user.driver

    # Check if this driver still have an outstanding order
    if Order.objects.filter(driver=driver, status=Order.ONTHEWAY):
      return JsonResponse({
        "status": "failed",
        "error": "Your outstanding order is not delivered yet."
      })

    # Process the picking up order
    try:
      order = Order.objects.get(
        id = request.POST["order_id"],
        driver = None,
        status = Order.READY
      )

      order.driver = driver
      order.status = Order.ONTHEWAY
      order.picked_at = timezone.now()
      order.save()

      return JsonResponse({
        "status": "success"
      })
    
    except Order.DoesNotExist:
      return JsonResponse({
        "status": "failed",
        "error": "This order has been picked up by another"
      })

def driver_get_latest_order(request):
  # Get access_token
  access_token = AccessToken.objects.get(
    token=request.GET.get("access_token"),
    expires__gt = timezone.now()
  )

  # Get Driver
  driver = access_token.user.driver

  # Get the latest order of this driver
  order = OrderSerializer(
    Order.objects.filter(driver=driver, status=Order.ONTHEWAY).last()
  ).data

  return JsonResponse({
    "order": order
  })

@csrf_exempt
def driver_complete_order(request):
  """
    params:
      1. access_token
      2. order_id
    return:
      {"status": "success"}
  """

  if request.method == "POST":
    # Get access token
    access_token = AccessToken.objects.get(
      token=request.POST.get("access_token"),
      expires__gt = timezone.now()
    )

    # Get driver
    driver = access_token.user.driver

    # Complete an order
    order = Order.objects.get(id = request.POST["order_id"], driver = driver)
    order.status = Order.DELIVERED
    order.save()

  return JsonResponse({
    "status": "success"
  })

def driver_get_revenue(request):
  return JsonResponse({})

@csrf_exempt
def driver_update_location(request):
  """
    params:
      1. access_token
      2. location Ex: lat, lng
    return:
      {"status": "success"}
  """
  if request.method == "POST":
    access_token = AccessToken.objects.get(
      token = request.POST["access_token"],
      expires__gt = timezone.now()
    )

    driver = access_token.user.driver
    driver.location = request.POST["location"]
    driver.save()

  return JsonResponse({
    "status": "success"
  })

def driver_get_profile(request):
  access_token = AccessToken.objects.get(
    token = request.GET["access_token"],
    expires__gt = timezone.now()
  )

  driver = OrderDriverSerializer(
    access_token.user.driver
  ).data

  return JsonResponse({
    "driver": driver
  })

@csrf_exempt
def driver_update_profile(request):
  """
    params:
      1. access_token
      2. car_model
      3. plate_number
    return:
      {"status": "success"}
  """

  if request.method == "POST":
    access_token = AccessToken.objects.get(
      token = request.POST["access_token"],
      expires__gt = timezone.now()
    )

    driver = access_token.user.driver

    # Update driver's profile
    driver.car_model = request.POST["car_model"]
    driver.plate_number = request.POST["plate_number"]
    driver.save()

  return JsonResponse({
    "status": "success"
  })