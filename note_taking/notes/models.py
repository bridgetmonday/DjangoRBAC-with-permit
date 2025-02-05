
from django.db import models
from django.contrib.auth.models import User
import uuid

# Define roles for notes
class NoteRole(models.TextChoices):
    ADMIN = 'admin', 'Admin'
    EDITOR = 'editor', 'Editor'
    READER = 'reader', 'Reader'

class Note(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    content = models.TextField()
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_notes')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class NoteAccess(models.Model):
    note = models.ForeignKey(Note, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=NoteRole.choices)
    assigned_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="assigned_roles")  # This field

    class Meta:
        unique_together = ('note', 'user')  # Ensure a user can't have multiple roles for the same note

    def __str__(self):
        return f"{self.user.username} - {self.role} for {self.note.title}"
