        using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.IdentityModel.Claims;

        public partial class _Default : System.Web.UI.Page
        {
            protected void Page_Load(object sender, EventArgs e)
            {
            }

            protected void _login_Authenticate(object sender, AuthenticateEventArgs e)
            {
                
                    FormsAuthentication.SetAuthCookie(_login.UserName, false);
                    var claims = new List<Claim>();
                    claims.Add(new Claim(System.IdentityModel.Claims.ClaimTypes.Name, _login.UserName));
                    List<ClaimsIdentity> identity = new List<ClaimsIdentity>();
                    identity.Add(new ClaimsIdentity(claims,"UserName"));
                    ClaimsPrincipal principal = new ClaimsPrincipal(new ClaimsIdentityCollection(identity));
                    var querystring = Request.QueryString.ToString();
                    HttpContext.Current.Response.Redirect("/mysts.ashx?"+ querystring);
                
            }
            

}