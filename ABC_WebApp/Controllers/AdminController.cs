using System;
using System.Linq;
using System.Web.Mvc;
using ABC_WebApp.Helpers;
using ABC_WebApp.Models;

namespace ABC_WebApp.Controllers
{
    public class AdminController : Controller
    {
        public ActionResult Dashboard()
        {
            if (!SessionHelper.IsLoggedIn) return RedirectToAction("Login", "Auth");
            if (!SessionHelper.IsAdmin) return RedirectToAction("Index", "Home");

            int year = DateTime.Now.Year;
            var scores = DbHelper.GetAllScores();
            var employees = DbHelper.GetAllEmployeesAdmin();

            var vm = new AdminDashboardViewModel
            {
                Scores = scores,
                Employees = employees,
                TotalEmployees = scores.Count,
                PassedPart1 = scores.Count(s => DbHelper.IsPassedInYear(s.Part1, s.Part1Timestamp, year)),
                PassedPart2 = scores.Count(s => DbHelper.IsPassedInYear(s.Part2, s.Part2Timestamp, year)),
                TotalActive = employees.Count(e => e.Active == "1"),
                TotalInactive = employees.Count(e => e.Active != "1"),
                CurrentYear = year
            };
            vm.NotPassedPart1 = vm.TotalEmployees - vm.PassedPart1;
            vm.NotPassedPart2 = vm.TotalEmployees - vm.PassedPart2;
            return View(vm);
        }

        [HttpGet]
        public JsonResult GetScoresJson(int? year)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);

            int selectedYear = year ?? DateTime.Now.Year;
            var scores = DbHelper.GetAllScoresForYear(selectedYear);

            var result = scores.Select(s => new {
                s.EmployeeID,
                s.UserName,
                s.Department,
                s.CompanyID,
                s.Local,
                Part1 = s.Part1 ?? "not pass",
                Part2 = s.Part2 ?? "not pass",
                s.Part1Timestamp,
                s.Part2Timestamp,
                Year = selectedYear
            });
            return Json(result, JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        public JsonResult GetYearsJson()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            var years = DbHelper.GetTrainingYears();
            // Always include current year even if no data yet
            int cy = DateTime.Now.Year;
            if (!years.Contains(cy)) years.Insert(0, cy);
            return Json(years, JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        public JsonResult GetEmployeesJson()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            return Json(DbHelper.GetAllEmployeesAdmin(), JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        public JsonResult GetEmployee(string id)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            var emp = DbHelper.GetEmployeeAdmin(id);
            if (emp == null) return Json(new { error = "Not found" }, JsonRequestBehavior.AllowGet);
            return Json(emp, JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        public JsonResult SaveEmployee(EmployeeFormModel model)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            if (string.IsNullOrWhiteSpace(model.EmployeeID) || string.IsNullOrWhiteSpace(model.UserName))
                return Json(new { success = false, message = "Employee ID and Name are required." });
            try
            {
                bool isNew = !DbHelper.EmployeeExists(model.EmployeeID);
                if (isNew) DbHelper.InsertEmployee(model);
                else DbHelper.UpdateEmployee(model);
                return Json(new { success = true, message = isNew ? "Employee added." : "Employee updated.", isNew });
            }
            catch (Exception ex) { return Json(new { success = false, message = ex.Message }); }
        }

        [HttpPost]
        public JsonResult ToggleActive(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                string s = DbHelper.ToggleEmployeeActive(empID);
                return Json(new { success = true, status = s });
            }
            catch (Exception ex) { return Json(new { success = false, message = ex.Message }); }
        }

        [HttpPost]
        public JsonResult DeleteEmployee(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                DbHelper.DeleteEmployee(empID);
                return Json(new { success = true, message = "Employee deleted." });
            }
            catch (Exception ex) { return Json(new { success = false, message = ex.Message }); }
        }
    }
}
