from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import Note, NoteAccess
from django.contrib import messages
import requests
import uuid


# this function helps to create a new resource instance of the note that was just created, Note: every note created has a unique id
# you might want to create a new resource instance for each note created
# if you get any error, you can check the permit.io documentation for more information
def create_permit_instance(note_id):
    url = "https://api.permit.io/v2/facts/{project_id}/{env_id}/resource_instances"
    headers = {
        "Authorization": "Bearer permit_key",
        "Content-Type": "application/json",
    }

    payload = {"key": note_id, "resource": "note", "tenant": "default"}

    response = requests.post(url, json=payload, headers=headers)

    print(f"response status code is {response.status_code}")
    print(
        f"Response Payload is:\n\n{response.json()}"
    )  # Assuming the response is in JSON format


# this function helps to get the role of a user for a specific note instance
# this would onlky help you retrive certain data of that user when you query the permit.io API for the user to get the permitted role if added to any instance based on the instanace id been looked up
def get_permit_user_instance_data(request, user_id, resource_instance):
    url = f"https://api.permit.io/v2/facts/{project_id}/{env_id}/role_assignments?user=user|{user_id}&resource_instance=note:{resource_instance}"
    headers = {
        "Authorization": "Bearer permit_key",
        "Content-Type": "application/json",
    }

    response = requests.get(url, headers=headers)
    print(f"response status code is {response.status_code} {response.text}")
    print(
        f"Response Payload is:\n\n{response.json()}"
    )  # Assuming the response is in JSON format

    if response.status_code == 200 or response.status_code == 201:
        try:
            return response.json()  # ✅ Return JSON data
        except requests.exceptions.JSONDecodeError:
            print("Error: Response is not a valid JSON")
            return None
    else:
        print(f"Permit API Error: {response.status_code}, {response.text}")
        return None


# this give the user a role access to a specific note instance
# this has nothing to do with adding the user to a tenant, it just gives the user a role access to a specific note instance,
# Note: the user must exist else you would get an error
# Note: you must specify both the resource type and resource instance like this (note:{resource_instance}) else you would get and error


def add_permit_user_to_note_instance(request, name, role, resource_instance):
    print(f"resource id is {resource_instance}")
    url = "https://api.permit.io/v2/facts/{project_id}/{env_id}/role_assignments"

    headers = {
        "Authorization": "Bearer permit_key",
        "Content-Type": "application/json",
    }

    payload = {
        "user": f"user|{name}",
        "role": role,
        "resource_instance": f"note:{resource_instance}",
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200 or response.status_code == 201:
        try:
            messages.success(request, "User added successfully to Permit.io.")
            return response  # ✅ Return JSON data
        except requests.exceptions.JSONDecodeError:

            print(f"Permit API Error: {response.status_code}, {response.text}")
            messages.error(request, "Error: Response is not a valid JSON")
            return None
    else:
        print(f"Permit API Error: {response.status_code}, {response.text}")
        messages.error(
            request, "An unexpected error occured why adding user to note instance"
        )
        return None


# this gives the user a top level role access, not really defined to a specific note


def add_permit_user(name, role):
    url = "https://api.permit.io/v2/facts/{project_id}/{env_id}/users"
    headers = {
        "Authorization": "Bearer permit_key",
        "Content-Type": "application/json",
    }

    payload = {
        "key": f"user|{name}",
        "email": f"{name}@noteapp.com",
        "first_name": f"{name}",
        "last_name": f"{name}",
        "role_assignments": [
            {"role": role, "tenant": "default"},
        ],
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 200 or response.status_code == 201:
        print(f"User added successfully to Permit.io: {response.json()}")
        return response  # Success

    print(f"Error: {response.status_code}, {response.text}")
    return None  # Ensure failure is correctly handled


# this controller just help to sign the user up to your register
# it also checks if the user is already logged in, if the user is already logged in, it redirects the user to the note list page
# it also checks if the username already exists, if it does, it returns an error message
# you might choose to update the function if you want to add more features


def register(request):
    if request.user.is_authenticated:
        return redirect("note_list")

    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        # Check if user already exists in the database
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect("register")

        # Call Permit API (without passing `request`)
        response = add_permit_user(username, "admin")

        # If Permit API call fails, do NOT create user
        if response is None:
            messages.error(request, "User already exist on permit.io")
            return redirect("register")

        # Create user only if Permit API was successful
        user = User.objects.create_user(username=username, password=password)
        login(request, user)
        return redirect("note_list")

    return render(
        request,
        "auth_form.html",
        {
            "form_type": "register",
            "submit_text": "Sign Up",
            "alternate_text": "Already have an account?",
            "redirect_url": "/login/",
            "redirect_label": "Login",
        },
    )


# Login controller, this controller helps to authenticate the user and log the user in
def user_login(request):
    if request.user.is_authenticated:
        return redirect("note_list")  # Redirect if user is already logged in

    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        # Check if the username exists
        if not User.objects.filter(username=username).exists():
            messages.error(request, "Username does not exist.")
            return redirect("login")  # Redirect to login if username does not exist

        # Authenticate the user with the provided username and password
        user = authenticate(request, username=username, password=password)

        # Check if the user exists and the credentials are correct
        if user is not None:
            login(request, user)
            return redirect("note_list")
        else:
            # Add error message for invalid credentials
            messages.error(request, "username or password is invalid")
            return redirect("login")  # Redirect to login if credentials are invalid

    return render(
        request,
        "auth_form.html",
        {
            "form_type": "login",
            "submit_text": "Login",
            "alternate_text": "Don't have an account?",
            "redirect_url": "/register/",
            "redirect_label": "Register",
        },
    )


# Logout controller, this controller just clear the user section
def user_logout(request):
    logout(request)
    return redirect("login")


# this controller helps to get the note by the note id
# it also checks if the user has the required role to access the note
# it also checks if the user has access to the note
# it also checks if the note id is valid
# for shared notes, it makes use of the get_permit_user_instance_data function to get the user role
@login_required
def get_notes_by_id(request, note_id):
    # Validate UUID format
    try:
        # This will raise a ValueError if the note_id is not a valid UUID
        note_id = uuid.UUID(note_id)
    except ValueError:
        messages.error(request, "The provided note ID is not valid.")
        return redirect("/")  # Or you can redirect to a more appropriate page.

    # Now safely query the database
    note = get_object_or_404(Note, id=note_id)

    # Check user's access to the note
    if note.creator == request.user:
        role_type = "admin"
    else:
        permit_response = get_permit_user_instance_data(
            request, request.user.username, note_id
        )

        if permit_response:
            if isinstance(permit_response, list) and permit_response:
                # Extract the highest role in case of multiple roles
                user_roles = [
                    entry.get("role") for entry in permit_response if "role" in entry
                ]
                user_role = (
                    max(
                        user_roles, key=lambda r: ["admin", "editor", "reader"].index(r)
                    )
                    if user_roles
                    else None
                )
            else:
                user_role = (
                    permit_response.get("role")
                    if isinstance(permit_response, dict)
                    else None
                )

            role_hierarchy = ["admin", "editor", "reader"]

            if user_role in role_hierarchy:
                role_type = user_role
            else:
                messages.error(
                    request, "You do not have the required role to access this note."
                )
                return redirect("/")
        else:
            messages.error(request, "You do not have access to this note.")
            return redirect("/")

    users_with_roles = NoteAccess.objects.filter(note=note).select_related("user")

    return render(
        request,
        "notes/note_view.html",
        {"note": note, "has_note_already": True, "role_type": role_type},
    )


# this controller helps to define the role of the user
def user_can_edit(user, note):
    return (
        user.is_superuser
        or user.groups.filter(name="Editor").exists()
        or note.creator == user
    )


# this controller helps to update the note
# it also checks if the user has the required role to update the note
# it also checks if the user has access to the note
@login_required
def update_note(request, note_id):
    note = get_object_or_404(
        Note,
        id=note_id,
    )  # Ensure user can only edit their own note

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        content = request.POST.get("content", "").strip()

        if not title or not content:
            messages.error(request, "Title and content cannot be empty.")
            return redirect(
                "update_note", note_id=note.id
            )  # Redirect back to update page

        # Update the note fields
        note.title = title
        note.content = content
        note.save()  # updated_at will be automatically updated

        # print(f'Updated note: {note.content} by user {request.user.password}')
        messages.success(request, "Note updated successfully!")
        return redirect("note_list")

    return render(
        request,
        "notes/note_view.html",
    )


# this controller helps to delete the note
# it also checks if the user has the required role to delete the note
# it also checks if the user has access to the note
@login_required
def delete_note_by_id(request, note_id):
    try:
        note = Note.objects.get(id=note_id)  # Explicitly check if the note exists
    except ObjectDoesNotExist:
        messages.error(request, "The note you are trying to delete does not exist.")
        return redirect("note_list")

    note.delete()
    messages.success(request, "Note deleted successfully!")
    print("Note deleted")
    return redirect("note_list")


# this controller helps to list the notes created by the user
# it also checks if the user has the required role to list the notes
# it also checks if the user has access to the notes
@login_required
def your_note_list(request):
    """List notes created by the user."""
    user_notes = Note.objects.filter(creator=request.user)

    items = []
    for note in user_notes:
        role_type = "admin"  # Creator always has admin role
        note_roles = NoteAccess.objects.filter(note=note)
        items.append(
            {
                "title": note.title,
                "description": note.content,
                "date": note.created_at,
                "id": note.id,
                "role_type": role_type,
            }
        )

    return render(request, "notes/note_list.html", {"items": items})


# this controller helps to list the notes shared with the user
# it also checks if the user has the required role to list the notes
@login_required
def shared_note_list(request):
    """List notes where the user has been assigned a role."""
    shared_notes = NoteAccess.objects.filter(user=request.user).select_related("note")

    items = []
    for access in shared_notes:
        note = access.note
        role_type = access.role  # Get user's assigned role

        note_roles = NoteAccess.objects.filter(note=note)
        for access in note_roles:
            items.append(
                {
                    "title": note.title,
                    "description": note.content,
                    "date": note.created_at,
                    "id": note.id,
                    "role_type": role_type,
                }
            )

    return render(request, "notes/note_list.html", {"items": items})


# this controller helps to list all the notes
# it also checks if the user has the required role to list the notes
# it also checks if the user has access to the notes


@login_required
def all_note_list(request):
    """List all notes: both created by the user and shared with them."""
    user_notes = Note.objects.filter(creator=request.user)
    shared_notes = NoteAccess.objects.filter(user=request.user).select_related("note")

    items = []

    # Notes created by user
    for note in user_notes:
        role_type = "admin"  # Creator always has admin role

        note_roles = NoteAccess.objects.filter(note=note)
        items.append(
            {
                "title": note.title,
                "description": note.content,
                "date": note.created_at,
                "id": note.id,
                "role_type": role_type,
            }
        )

    # Notes shared with user
    for access in shared_notes:
        note = access.note
        role_type = access.role  # Get user's assigned role

        note_roles = NoteAccess.objects.filter(note=note)
        items.append(
            {
                "title": note.title,
                "description": note.content,
                "date": note.created_at,
                "id": note.id,
                "role_type": role_type,
            }
        )

    return render(request, "notes/note_list.html", {"items": items})


# this controller helps to create a new note
@login_required
def create_notes(request):
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        content = request.POST.get("content", "").strip()

        if not title or not content:
            messages.error(request, "Title and content cannot be empty.")
            return redirect("new_note")

        note = Note.objects.create(title=title, content=content, creator=request.user)
        create_permit_instance(f"{note.id}")
        messages.success(request, "Note created successfully!")
        return redirect("note_list")

    return render(
        request,
        "notes/note_view.html",
        {"role_type": "admin", "has_note_already": True},
    )


@login_required
def new_note(request):

    return render(
        request,
        "notes/note_view.html",
        {
            "has_note_already": False,
            "role_type": "admin",
        },
    )


# this controller helps to add a user role to a note
def add_user_role(request, note_id):
    note = get_object_or_404(
        Note,
        id=note_id,
    )  # Ensure only creator can add roles

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        role = request.POST.get("role", "").strip()

        # Check if the username and role are provided
        if not username or not role:
            messages.error(request, "Username and role are required.")
            return render(
                request,
                "notes/note_view.html",
                {"note": note, "role_type": "admin", "has_note_already": True},
            )

        # Check if the user exists in the database
        user = User.objects.filter(username=username).first()
        if not user:
            messages.error(request, "Username does not exist.")
            return render(
                request,
                "notes/note_view.html",
                {"note": note, "role_type": "admin", "has_note_already": True},
            )

        # Proceed with adding the user to Permit.io
        response = add_permit_user_to_note_instance(
            request, user.username, role, note_id
        )

        # Check if the response was successful and display message
        if response and (response.status_code == 200 or response.status_code == 201):
            # Create or update the role in the local database
            note_access, created = NoteAccess.objects.update_or_create(
                note=note,
                user=user,
                defaults={"role": role, "assigned_by": request.user},
            )

        return render(
            request,
            "notes/note_view.html",
            {"note": note, "role_type": "admin", "has_note_already": True},
        )

    return render(
        request,
        "notes/note_view.html",
        {"note": note, "role_type": "admin", "has_note_already": True},
    )
