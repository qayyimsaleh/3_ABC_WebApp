using System.Web.Mvc;
using ABC_WebApp.Helpers;

namespace ABC_WebApp.Controllers
{
    public class ProfileController : Controller
    {
        public ActionResult Index()
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");
            var emp = DbHelper.GetEmployee(SessionHelper.EmployeeID);
            if (emp == null)
                return RedirectToAction("Login", "Auth");
            return View(emp);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(string currentPassword, string newPassword, string confirmPassword)
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");

            var emp = DbHelper.GetEmployee(SessionHelper.EmployeeID);
            if (emp == null)
                return RedirectToAction("Login", "Auth");

            if (string.IsNullOrEmpty(currentPassword) || emp.EmployeeIC != currentPassword)
            {
                TempData["Error"] = "Current password is incorrect.";
                return RedirectToAction("Index");
            }

            if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
            {
                TempData["Error"] = "New password must be at least 6 characters.";
                return RedirectToAction("Index");
            }

            if (newPassword != confirmPassword)
            {
                TempData["Error"] = "New passwords do not match.";
                return RedirectToAction("Index");
            }

            if (newPassword == currentPassword)
            {
                TempData["Error"] = "New password must be different from the current one.";
                return RedirectToAction("Index");
            }

            DbHelper.UpdatePassword(SessionHelper.EmployeeID, newPassword);

            string ip = Request.ServerVariables["HTTP_X_FORWARDED_FOR"] ?? Request.ServerVariables["REMOTE_ADDR"] ?? "unknown";
            string role = SessionHelper.IsAdmin ? "Admin" : "Employee";
            DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, role,
                "CHANGE_PASSWORD", SessionHelper.EmployeeID, SessionHelper.UserName, null, ip.Split(',')[0].Trim(), "SUCCESS");

            TempData["Success"] = "Password updated successfully.";
            return RedirectToAction("Index");
        }
    }
}
