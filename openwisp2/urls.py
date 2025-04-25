from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path, reverse_lazy
from django.views.generic import RedirectView
# from django.views.generic import TemplateView 
# from nexappvpn.wizards import TunnelCreationWizard,FORMS

# from nexappvpn.forms import TunnelStep1Form, TunnelStep2Form, TunnelStep3Form
from django.contrib.admin.views.decorators import staff_member_required

redirect_view = RedirectView.as_view(url=reverse_lazy('admin:index'))

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('openwisp_controller.urls')),
    path('api/v1/', include('openwisp_utils.api.urls')),
    path('api/v1/', include('openwisp_users.api.urls')),
    path('/', include('openwisp_network_topology.urls')),
    path('', include('openwisp_monitoring.urls')),
    path('', include('openwisp_radius.urls')),
    path('api/nexappvpn/', include('nexapp_vpn.urls')),
    path('', redirect_view, name='index'),
    path('vpn/ipsec/', include('vpn_ipsec.urls')),
    # path('vpn/', TemplateView.as_view(template_name='index.html')),
#     path(
#     'wizard/tunnel/',
#     staff_member_required(
#         TunnelCreationWizard.as_view(form_list=dict(FORMS)) 
#     ),
#     name='tunnel_wizard'
# )
    # path('wizard/tunnel/', staff_member_required(TunnelCreationWizard.as_view(dict(FORMS))),name='tunnel_wizard'),
    # path('wizard/tunnel/', staff_member_required(TunnelCreationWizard.as_view([TunnelStep1Form, TunnelStep2Form, TunnelStep3Form])), name='tunnel_wizard'),
]


urlpatterns += staticfiles_urlpatterns()
