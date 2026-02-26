using System;
using System.Linq;
using System.Web.Mvc;
using ABC_WebApp.Helpers;
using ABC_WebApp.Models;

namespace ABC_WebApp.Controllers
{
    public class AdminController : Controller
    {
        // ── GET /Admin/Dashboard ─────────────────────────────────────────────
        public ActionResult Dashboard()
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");

            if (!SessionHelper.IsAdmin)
            {
                TempData["ErrorMessage"] = "You do not have permission to access the Admin Dashboard.";
                return RedirectToAction("Index", "Home");
            }

            int  year   = DateTime.Now.Year;
            var  scores = DbHelper.GetAllScores();

            var vm = new AdminDashboardViewModel
            {
                Scores         = scores,
                TotalEmployees = scores.Count,
                PassedPart1    = scores.Count(s => DbHelper.IsPassedInYear(s.Part1, s.Part1Timestamp, year)),
                PassedPart2    = scores.Count(s => DbHelper.IsPassedInYear(s.Part2, s.Part2Timestamp, year)),
                CurrentYear    = year
            };
            vm.NotPassedPart1 = vm.TotalEmployees - vm.PassedPart1;
            vm.NotPassedPart2 = vm.TotalEmployees - vm.PassedPart2;

            return View(vm);
        }

        // ── AJAX GET /Admin/GetScoresJson  (DataTable live reload) ───────────
        [HttpGet]
        public JsonResult GetScoresJson()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);

            int year   = DateTime.Now.Year;
            var scores = DbHelper.GetAllScores();

            var result = scores.Select(s => new
            {
                s.EmployeeID,
                s.UserName,
                s.Department,
                s.CompanyID,
                s.Local,
                Part1           = DbHelper.IsPassedInYear(s.Part1, s.Part1Timestamp, year) ? "pass" : "not pass",
                Part2           = DbHelper.IsPassedInYear(s.Part2, s.Part2Timestamp, year) ? "pass" : "not pass",
                s.Part1Timestamp,
                s.Part2Timestamp
            });

            return Json(result, JsonRequestBehavior.AllowGet);
        }
    }
}
