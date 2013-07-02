using System;
using System.Linq;
using System.Web;
using System.Security.Principal;
using System.Configuration;
using Microsoft.IdentityModel.Claims;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Web;

/// <summary>
/// Summary description for SecurityTokenService
/// </summary>
public class SimpleWebTokenHandler : IHttpHandler
{
    public bool IsReusable
    {
        get 
        {
            return true;
        }
    }

    public void ProcessRequest(HttpContext context)
    {

        if (context.User == null || !context.User.Identity.IsAuthenticated)
        {
            string querystring = context.Request.QueryString.ToString();
            context.Response.Redirect("/Default.aspx?" + querystring);
        }
        //var winPrincipal = context.User as WindowsPrincipal;
        //if (winPrincipal == null || !winPrincipal.Identity.IsAuthenticated)
        //    throw new ConfigurationException("This web site is not correctly configured for Windows authentication.");

        var values = context.Request.QueryString;
        var realm = values["realm"] ?? "relying_party_not_specified";
        var reply = values["redirect_uri"];
        var deflate = "true".Equals(values["deflate"], StringComparison.OrdinalIgnoreCase);

        var principal = ClaimsPrincipal.CreateFromPrincipal(context.User);
      //  var principal = ClaimsPrincipal.CreateFromPrincipal(context.User); 
        var identity = ClaimsPrincipal.SelectPrimaryIdentity(principal.Identities);

        var issuer = context.Request.Url.AbsoluteUri;
        var idx = issuer.IndexOf("?");
        if (idx != -1)
            issuer = issuer.Substring(0, idx);
        var token = this.CreateToken(identity.Claims, issuer, realm);
        NameValueCollection queryString;
        if (!String.IsNullOrEmpty(reply))
        {
            string path;
            idx = reply.IndexOf('?');
            if (idx != -1)
            {
                path = reply.Substring(0, idx);
                queryString = HttpUtility.ParseQueryString(reply.Substring(idx + 1));
            }
            else
            {
                path = reply;
                queryString = new NameValueCollection();
            }
            this.WrapSWT(queryString, token, deflate);
            path = String.Concat(path, ToQueryString(queryString));
            var uri = new Uri(new Uri(realm), path);
            context.Response.Redirect(uri.AbsoluteUri, false);
            return;
        }

        queryString = new NameValueCollection();
        this.WrapSWT(queryString, token, deflate);

        context.Response.Clear();
        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/plain";
        context.Response.Write(ToQueryString(queryString, false));
    }

    private SimpleWebToken CreateToken(ClaimCollection claims, string issuerName, string appliesTo)
    {
        appliesTo = appliesTo.ToLower();

        var sKey = ConfigurationManager.AppSettings[appliesTo];
        if (String.IsNullOrEmpty(sKey))
        {
            //check if appliesTo failed to find the key because it's missing a trailing slash, 
            //or because it has a trailing slash which shouldn't be there
            //and act accordingly (and try again):
            if (!appliesTo.EndsWith("/"))
                appliesTo += "/";
            else
                appliesTo = VirtualPathUtility.RemoveTrailingSlash(appliesTo);

            sKey = ConfigurationManager.AppSettings[appliesTo];
            if (String.IsNullOrEmpty(sKey))
                throw new ConfigurationException(String.Format("Missing symmetric key for \"{0}\".", appliesTo));
        }
        var key = this.HexToByte(sKey);

        var sb = new StringBuilder();
        foreach (var c in claims)
            sb.AppendFormat("{0}={1}&", HttpUtility.UrlEncode(c.ClaimType), HttpUtility.UrlEncode(c.Value));

        double lifeTimeInSeconds = 3600;
        sb
            .AppendFormat("TokenId={0}&", HttpUtility.UrlEncode(Guid.NewGuid().ToString()))
            .AppendFormat("Issuer={0}&", HttpUtility.UrlEncode(issuerName))
            .AppendFormat("Audience={0}&", HttpUtility.UrlEncode(appliesTo))
            .AppendFormat("ExpiresOn={0:0}", (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds + lifeTimeInSeconds);

        var unsignedToken = sb.ToString();

        var hmac = new HMACSHA256(key);
        var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(unsignedToken));

        string signedToken = String.Format("{0}&HMACSHA256={1}",
            unsignedToken,
            HttpUtility.UrlEncode(Convert.ToBase64String(sig)));

        return new SimpleWebToken(signedToken);
    }

    private void WrapSWT(NameValueCollection collection, SimpleWebToken token, bool deflate)
    {
        var rawToken = token.RawToken;
        if (deflate)
        {
            var zipped = this.ZipStr(rawToken);
            rawToken = Convert.ToBase64String(zipped);
            collection["wrap_deflated"] = "true";
        }
        collection["wrap_access_token"] = HttpUtility.UrlEncode(rawToken);
        var seconds = Convert.ToInt32((token.ValidTo - token.ValidFrom).TotalSeconds);
        collection["wrap_access_token_expires_in"] = seconds.ToString();
    }

    private byte[] ZipStr(String str)
    {
        using (MemoryStream output = new MemoryStream())
        {
            using (DeflateStream gzip = new DeflateStream(output, CompressionMode.Compress))
            {
                using (StreamWriter writer = new StreamWriter(gzip, System.Text.Encoding.UTF8))
                {
                    writer.Write(str);
                }
            }

            return output.ToArray();
        }
    }

    private byte[] HexToByte(string hexString)
    {
        byte[] returnBytes = new byte[hexString.Length / 2];
        for (int i = 0; i < returnBytes.Length; i++)
            returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        return returnBytes;
    }

    public static string ToQueryString(NameValueCollection collection, bool startWithQuestionMark = true)
    {
        if (collection == null || !collection.HasKeys())
            return String.Empty;

        var sb = new StringBuilder();
        if (startWithQuestionMark)
            sb.Append("?");

        var j = 0;
        var keys = collection.Keys;
        foreach (string key in keys)
        {
            var i = 0;
            var values = collection.GetValues(key);
            foreach (var value in values)
            {
                sb.Append(key)
                    .Append("=")
                    .Append(value);

                if (++i < values.Length)
                    sb.Append("&");
            }
            if (++j < keys.Count)
                sb.Append("&");
        }
        return sb.ToString();
    }
}