using System;
using System.Web.Mvc;
using ABC_WebApp.Helpers;
using ABC_WebApp.Models;

namespace ABC_WebApp.Controllers
{
    public class HomeController : Controller
    {
        // ── GET /Home/Index  (Dashboard) ─────────────────────────────────────
        public ActionResult Index()
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");

            int  year  = DateTime.Now.Year;
            var  emp   = DbHelper.GetEmployee(SessionHelper.EmployeeID);
            var  score = DbHelper.GetEmployeeScore(SessionHelper.EmployeeID, SessionHelper.UserName);

            bool part1 = score != null && DbHelper.IsPassedInYear(score.Part1, score.Part1Timestamp, year);
            bool part2 = score != null && DbHelper.IsPassedInYear(score.Part2, score.Part2Timestamp, year);

            var vm = new DashboardViewModel
            {
                CurrentEmployee = emp,
                Part1Status     = part1 ? "pass" : "not pass",
                Part2Status     = part2 ? "pass" : "not pass",
                IsPart2Unlocked = part1,
                CurrentYear     = year,
                IsSuperUser     = SessionHelper.IsAdmin,
                ErrorMessage    = TempData["ErrorMessage"]?.ToString()
            };

            return View(vm);
        }
    }
}
