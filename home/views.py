from django.shortcuts import render



def the_exchange(request):
    return render(request,'home/the_exchange.html')

def Media_Center(request):
    return render(request,'home/Media_Center.html')

def About_us(request):
    return render(request,'home/About_us.html')

def Add_Form(request):
    return render(request,'home/Add_Form.html')

def Career(request):
    return render(request,'home/Career.html')

def Daily_Downloads(request):
    return render(request,'home/Daily_Downloads.html')

def landing_page(request):
    return render(request,'home/landing_page.html')

def legal_framwork(request):
    return render(request,'home/legal_framwork.html')

def Market_Summary(request):
    return render(request,'home/Market_Summary.html')