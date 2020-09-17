from django.urls import path
from .views import (
    AuthTestApiView
)

app_name = 'test_app'

urlpatterns = [
    path('foo', AuthTestApiView.as_view()),
]
