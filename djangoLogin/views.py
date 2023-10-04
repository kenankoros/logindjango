from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from djangoLogin import settings
from .tokens import generate_token


def home(request):
    return render(request, "index.html")


def signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try another username")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request, "email already exist!")
            return redirect('home')

        if len(username) > 10:
            messages.error(request, "username must not be greater than 10 characters!!")
            return

        if pass1 != pass2:
            messages.error(request, "password did not match!")

        if not username.isalnum():
            messages.error(request, "Username must be alpha-numeric!")
            return redirect('home')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "your account as been successfully created. We have sent you a confirmantion email please confirm inorder to activate your account. ")

        subject = "Welcome to Nu flava were you get all you need!"
        message = "hello" + myuser.first_name + "!!\n" + "Welcome to Nu Collection \n" + "Thank you for visiting our website!\n " + "please confirm you email address in order to activate your account!\n \n Thanking you \n Timothy Koros"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        current_site = get_current_site(request)
        email_subject = "confirm your email @ Nu Flava"
        message2 = render_to_string('email_confirmation.html'), {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        }

        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],

        )
        email.fail_silenty = True
        email.send()

        return redirect('signin')

    return render(request, "signup.html")


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)

        if user is None:
            login(request, user)
            fname = User.first_name
            return render(request, "index.html", {'fname': fname})

        else:
            messages.error(request, "invalid details")
            return redirect('home')

    return render(request, "signin.html")


def signout(request):
    logout(request)
    messages.success(request, "logged out successfully")
    return redirect('home')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    else:
        return render(request, 'activation_fail.html')
