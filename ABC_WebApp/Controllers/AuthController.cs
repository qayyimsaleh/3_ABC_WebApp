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
                    ModelState.AddModelError("", "Incorrect password. Please try again.");
                    return View(model);
                }

                SessionHelper.SetSession(emp);
                return RedirectToAction("Index", "Home");
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "A system error occurred. Please try again or contact IT Support.");
                return View(model);
            }
        }

        // ── GET /Auth/Logout ─────────────────────────────────────────────────
        public ActionResult Logout()
        {
            SessionHelper.Clear();
            return RedirectToAction("Login");
        }

        // ── AJAX /Auth/LookupEmployee?id=xxx  (live name preview on login page) ──
        [HttpGet]
        [AllowAnonymous]
        public JsonResult LookupEmployee(string id)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(id))
                    return Json(new { found = false }, JsonRequestBehavior.AllowGet);

                var emp = DbHelper.GetEmployee(id.Trim());
                if (emp == null)
                    return Json(new { found = false }, JsonRequestBehavior.AllowGet);

                // Return only minimum info needed for UX — do NOT expose department
                // or other details that could be harvested for social engineering
                return Json(new
                {
                    found = true,
                    name = emp.UserName,
                    access = emp.Access
                }, JsonRequestBehavior.AllowGet);
            }
            catch
            {
                return Json(new { found = false }, JsonRequestBehavior.AllowGet);
            }
        }
    }
}
