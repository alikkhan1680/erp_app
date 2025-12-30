from django.contrib import admin
from django.urls import path, include, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(
        title="My Project API",
        default_version='v1',
        description="Loyiha API documentation",
    ),
    public=True,
    permission_classes=(permissions.IsAuthenticated,),  # agar token talab qilinsa
)

urlpatterns = [

    path('accounts/', include('accounts.urls')),  # <-- accounts ichidagi urls.py
    path('admin/', admin.site.urls),
    path('auth/', include('auth_module.urls')),
    #swagger
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

]
