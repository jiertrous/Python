from django.contrib.auth import authenticate, login,logout
from django.conf import settings
from django.shortcuts import render,redirect
from django.urls import reverse
from django.views.generic import View
from django.core.mail import send_mail
from django.http import HttpResponse
from user.models import User,Address
from celery_tasks.tasks import send_register_active_email
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
from utils.miaxin import LoginRequiredMixin
import time  # 等待时间
import re

# Create your views here.

# /user/register

def register(request):
    '''注册'''
    if request.method == 'GET':
        # 显示注册页面
        return render(request, 'register.html')
    else:
        # 进行注册处理
        # 接收数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 进行数据校验
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不正确'})

        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 校验用户名是否重复
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None

        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})

        # 进行业务处理: 进行用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

        # 返回应答, 跳转到首页
        return redirect(reverse('goods:index'))


def register_handle(request):
    '''进行注册处理'''
    # 接收数据
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    email = request.POST.get('email')
    allow = request.POST.get('allow')

    # 进行数据校验
    if not all([username, password, email]):
        # 数据不完整
        return render(request, 'register.html', {'errmsg':'数据不完整'})

    # 校验邮箱
    if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
        return render(request, 'register.html', {'errmsg':'邮箱格式不正确'})

    if allow != 'on':
        return render(request, 'register.html', {'errmsg':'请同意协议'})

    # 校验用户名是否重复
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        # 用户名不存在
        user = None

    if user:
        # 用户名已存在
        return render(request, 'register.html', {'errmsg':'用户名已存在'})

    # 进行业务处理: 进行用户注册
    user = User.objects.create_user(username, email, password)
    user.is_active = 0
    user.save()

    # 返回应答, 跳转到首页
    return redirect(reverse('goods:index'))

class RegisterView(View):
    '''注册'''
    def get(self, request):
        '''显示注册页面'''
        return render(request, 'register.html')

    def post(self, request):
        '''进行注册处理'''
        # 接收数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 进行数据校验
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不正确'})

        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 校验用户名是否重复
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None

        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})

        # 进行业务处理: 进行用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

        # 发送激活邮件，包含激活链接: http://127.0.0.1:8000/user/active/3
        # 激活链接中需要包含用户的身份信息, 并且要把身份信息进行加密

        # 加密用户的身份信息，生成激活token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm':user.id}
        token = serializer.dumps(info) # bytes
        token = token.decode()  # 转化为字符串，decode默认utf8，可省略

        # 发邮件
        send_register_active_email.delay(email, username, token)
        # time.sleep(5) # 使用smtp导致注册之后，需要等待smtp发送玩  模拟等待时间
        # 返回应答, 跳转到首页
        return redirect(reverse('goods:index'))


class ActiveView(View):
    """用户激活"""
    def get(self,request,token):
        """进行用户激活"""
        # 进行解密 获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
           info =  serializer.loads(token)
           # 获取待激活用户的id
           user_id = info['confirm']

           # 根据id获取用户信息
           user = User.objects.get(id=user_id)
           user.is_active = 1
           user.save()

           # 返回应答跳转到登陆页面
           return redirect(reverse('user:login'))
        except SignatureExpired as e:
            # 激活链接已过期
            return HttpResponse("激活链接已过期")


# /user/login
class LoginView(View):
    """登陆"""
    def get(self, request):
        '''显示登录页面'''
        # 判断是否记住了用户名
        if 'username' in request.COOKIES:
            username = request.COOKIES.get('username')
            checked = 'checked'
        else:
            username = ''
            checked = ''

        # 使用模板
        return render(request, 'login.html', {'username':username, 'checked':checked})

    def post(self, request):
        '''登录校验'''
        # 接收数据
        username = request.POST.get('username')
        password = request.POST.get('pwd')

        # 校验数据
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg':'数据不完整'})

        # 业务处理:登录校验
        user = authenticate(username=username, password=password)
        if user is not None:
            # 用户名密码正确
            if user.is_active:
                # 用户已激活
                # 记录用户的登录状态
                login(request, user)

                # 获取登陆后要跳转的地址,参数next的地址
                # 默认跳转到首页
                next_url = request.GET.get('next',reverse('goods:index')) # None

                # 跳转到首页
                response = redirect(next_url) # HttpResponseRedirect

                # 判断是否需要记住用户名
                remember = request.POST.get('remember')

                if remember == 'on':
                    # 记住用户名
                    response.set_cookie('username', username, max_age=7*24*3600)
                else:
                    response.delete_cookie('username')

                # 返回response
                return response
            else:
                # 用户未激活
                return render(request, 'login.html', {'errmsg':'账户未激活'})
        else:
            # 用户名或密码错误
            return render(request, 'login.html', {'errmsg':'用户名或密码错误'})

# 退出
class LogoutView(View):
    """退出"""
    def get(self,request):
        """推出信息"""
        # 清楚用户的session信息
        logout(request)

        # 跳转到首页
        return redirect(reverse('goods:index'))

# user/
class UserInfoView(LoginRequiredMixin,View):
    """用户中心-信息页"""
    def get(self,request):
        """显示"""
        # page='user
        # request.user.is_authenticated()
        # 如果用户未登录->AnonymousUser的一个实例
        # 如果用户登陆->User类的一个实例
        # request.user.is_authenticated()

        # 获取用户的个人信息

        # 获取用户的历史浏览记录

        # 除了你给模板传送的模板变量之外，django框架会把request.useru也传给模板文件
        return render(request,'user_center_info.html',{'page':'user'})

# user/order
class UserOrderView(LoginRequiredMixin,View):
    """用户中心-订单"""
    def get(self,request):
        """显示"""
        # 获取用户的订单页面
        return render(request,'user_center_order.html',{'page':'order'})

# user/address
class AddressView(LoginRequiredMixin,View):
    """用户中心-地址页"""
    def get(self, request):
        """显示"""
        # 获取用户默认收货地址
        user = request.user # 获取用户对应的user

        # 获取用户默认收货地址
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #      # 不存在默认收货地址
        #     address = None
        address = Address.objects.get_default_address(user)

        # 使用模板的时候传过去
        return render(request,'user_center_site.html',{'page':'address','address':'address'})

    def post(self, request):
        """地址的添加"""
        # 接受数据
        receiver = request.POST.get('recerver')
        addr = request.POST.get('addr')
        zip_code = request.POST.get('zip_code')
        phone = request.POST.get('phone')

        # 校验数据
        if not all([receiver,addr,phone]):
            return render(request,'user_center_site.html',{'errmsg':'数据信息不完整'})
        # 校验手机号
        if not re.match(r'^1[3|4|5|7|8][0-9]{9}$', phone):
            return render(request,'user_center_site.html',{'errmsg':'请输入正确的手机号码'})

        # 业务处理，地址添加
        # 如果用户已存在默认收货地址，添加的地址不作为默认地址，否则作为默认收货地址
        # 先判断是否有默认收货地址
        user = request.user # 获取用户对应的user
        # 获取用户默认收货地址
        # try:
        #     address = Address.objects.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #      #　不存在默认收货地址
        #     address = None

        address = Address.objects.get_default_address(user)


        if address:
            is_default = False
        else:
            is_default = True

        # 添加地址
        Address.objects.create(user=user,
                               receiver=receiver,
                               addr=addr,
                               zip_code=zip_code,
                               phone=phone,
                               is_default=is_default)


        # 返回应答，返回地址页面
        return redirect(reverse('user:address')) # get访问方式


