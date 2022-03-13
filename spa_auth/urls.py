from django.urls import path

from spa_auth.views import RegisterAPIView

urlpatterns = [
    path('register', RegisterAPIView.as_view())
]
