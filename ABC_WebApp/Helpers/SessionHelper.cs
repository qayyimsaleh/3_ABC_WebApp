using System.Web;
using ABC_WebApp.Models;

namespace ABC_WebApp.Helpers
{
    /// <summary>Centralised session wrapper – keeps key names in one place.</summary>
    public static class SessionHelper
    {
        public static string EmployeeID => HttpContext.Current.Session["EmployeeID"]?.ToString();
        public static string UserName   => HttpContext.Current.Session["UserName"]?.ToString();
        public static string Department => HttpContext.Current.Session["Department"]?.ToString();
        public static string CompanyID  => HttpContext.Current.Session["CompanyID"]?.ToString();
        public static string SuperUser  => HttpContext.Current.Session["SuperUser"]?.ToString();
        public static bool   IsLoggedIn => !string.IsNullOrEmpty(EmployeeID);
        public static bool   IsAdmin    => SuperUser == "1";

        public static void SetSession(Employee emp)
        {
            var s = HttpContext.Current.Session;
            s["EmployeeID"] = emp.EmployeeID;
            s["UserName"]   = emp.UserName;
            s["Department"] = emp.Department;
            s["CompanyID"]  = emp.CompanyID;
            s["SuperUser"]  = emp.SuperUser;
            s["Access"]     = emp.Access;
        }

        public static void Clear()
        {
            HttpContext.Current.Session.Clear();
            HttpContext.Current.Session.Abandon();
        }
    }
}
