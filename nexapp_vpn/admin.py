
 
from django.contrib import admin
from django.utils.html import format_html
from django.urls import path
from django.shortcuts import redirect
from django.contrib import messages
from .models import Tunnel, TunnelStatusLog, TunnelConfigHistory, TunnelHealthMetric, DevicePeer
 
# @admin.register(Tunnel)
# class TunnelAdmin(admin.ModelAdmin):
#     list_display = ['name', 'status']
#     list_filter = ['status']
#     search_fields = ['name']

@admin.register(Tunnel)
class TunnelAdmin(admin.ModelAdmin):
    list_display = ('name','vpn_type', 'mode', 'status', 'organization', 'last_pushed_at', 'push_button', 'rollback_button')
    list_filter = ('vpn_type', 'mode', 'status', 'organization')
    search_fields = ('name', 'organization__name')
    readonly_fields = ('last_config_hash', 'last_pushed_at')
 
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<int:tunnel_id>/push/', self.admin_site.admin_view(self.process_push), name='vpn_tunnel_push'),
            path('<int:tunnel_id>/rollback/', self.admin_site.admin_view(self.process_rollback), name='vpn_tunnel_rollback'),
        ]
        return custom_urls + urls
 
    def push_button(self, obj):
        return format_html('<a class="button" href="{}">Push</a>', f'./{obj.pk}/push/')
 
    def rollback_button(self, obj):
        return format_html('<a class="button" href="{}">Rollback</a>', f'./{obj.pk}/rollback/')
 
    push_button.short_description = 'Push'
    rollback_button.short_description = 'Rollback'
 
    def process_push(self, request, tunnel_id):
        tunnel = Tunnel.objects.get(pk=tunnel_id)
        result = tunnel.push_to_agent()
        self.message_user(request, result['message'], messages.SUCCESS if result['status'] == 'success' else messages.ERROR)
        return redirect(request.META.get('HTTP_REFERER'))
 
    def process_rollback(self, request, tunnel_id):
        tunnel = Tunnel.objects.get(pk=tunnel_id)
        result = tunnel.rollback_last_config()
        self.message_user(request, result['message'], messages.SUCCESS if result['status'] == 'success' else messages.ERROR)
        return redirect(request.META.get('HTTP_REFERER'))
 
 

admin.site.register(TunnelStatusLog)
admin.site.register(TunnelConfigHistory)
admin.site.register(TunnelHealthMetric)
admin.site.register(DevicePeer)


