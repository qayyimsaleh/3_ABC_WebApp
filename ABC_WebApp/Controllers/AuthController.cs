using System;
using System.Threading;
using System.Web.Mvc;
using ABC_WebApp.Helpers;
using ABC_WebApp.Models;

namespace ABC_WebApp.Controllers
{
    public class AuthController : Controller
    {
        // ── GET /Auth/Login ──────────────────────────────────────────────────
        [AllowAnonymous]
        public ActionResult Login()
        {
            if (SessionHelper.IsLoggedIn)
                return RedirectToAction("Index", "Home");
            return View(new LoginViewModel());
        }

        // ── POST /Auth/Login ─────────────────────────────────────────────────
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            try
            {
                var emp = DbHelper.GetEmployee(model.Username?.Trim());

                if (emp == null)
                {
                    ModelState.AddModelError("", "Employee ID not found in the system.");
                    return View(model);
                }

                if (emp.Access == "0")
                {
                    Thread.Sleep(1500);
                    ModelState.AddModelError("", "Your account does not have portal access. Please contact Admin.");
                    return View(model);
                }

                if (emp.EmployeeIC != model.Password)
                {
                    Thread.Sleep(1500);
                    DbHelper.WriteLog(model.Username?.Trim() ?? "", emp.UserName, "Employee",
                        "LOGIN_FAIL", null, null, "Wrong password", GetIP(), "FAIL");
                    ModelState.AddModelError("", "Incorrect password. Please try again.");
                    return View(model);
                }

                SessionHelper.SetSession(emp);
                string role = emp.SuperUser == "1" ? "Admin" : "Employee";
                DbHelper.WriteLog(emp.EmployeeID, emp.UserName, role,
                    "LOGIN", null, null, null, GetIP(), "SUCCESS");
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(model.Username ?? "", "", "Unknown",
                    "LOGIN", null, null, ex.Message, GetIP(), "FAIL");
                ModelState.AddModelError("", "A system error occurred. Please try again or contact IT Support.");
                return View(model);
            }
        }

        // ── GET /Auth/Ping  (session keepalive — called every 4 min by JS) ──
        [HttpGet]
        public JsonResult Ping()
        {
            // Simply touching the session extends its sliding expiry.
            // Returns 200 if logged in, 401 if session has already expired.
            if (!SessionHelper.IsLoggedIn)
                return Json(new { ok = false }, JsonRequestBehavior.AllowGet);
            return Json(new { ok = true }, JsonRequestBehavior.AllowGet);
        }

        // ── GET /Auth/Logout ─────────────────────────────────────────────────
        public ActionResult Logout()
        {
            if (SessionHelper.IsLoggedIn)
            {
                string role = SessionHelper.IsAdmin ? "Admin" : "Employee";
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, role,
                    "LOGOUT", null, null, null, GetIP(), "SUCCESS");
            }
            SessionHelper.Clear();
            return RedirectToAction("Login");
        }

        private string GetIP()
        {
            string ip = Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            if (string.IsNullOrEmpty(ip)) ip = Request.ServerVariables["REMOTE_ADDR"];
            return ip?.Split(',')[0].Trim() ?? "unknown";
        }
    }
}
