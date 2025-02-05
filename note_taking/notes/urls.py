
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('create/', views.create_notes, name='create_note'),
    path('note/<uuid:note_id>/add-role/', views.add_user_role, name='add_user_role'),
    path('note/<uuid:note_id>/update/', views.update_note, name='update_note'),
    path('', views.all_note_list, name='all_note_list'),
    path('notes/shared-notes/', views.shared_note_list, name='shared_note_list'),
    path('notes/your-notes/', views.your_note_list, name='note_list'),
    path('new_note/', views.new_note, name='new_note'),
    path('note/<str:note_id>/', views.get_notes_by_id, name='note_detail'),
    path('note/delete/<str:note_id>/', views.delete_note_by_id, name='delete_note_by_id')
]
