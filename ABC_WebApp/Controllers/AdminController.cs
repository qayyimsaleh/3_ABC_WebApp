using System;
using System.Collections.Generic;
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
        public JsonResult GetScoresJson(string dateFrom, string dateTo)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);

            DateTime from = DateTime.TryParse(dateFrom, out DateTime df) ? df.Date : new DateTime(DateTime.Now.Year, 1, 1);
            DateTime to = DateTime.TryParse(dateTo, out DateTime dt) ? dt.Date : DateTime.Now.Date;

            var scores = DbHelper.GetAllScoresForDateRange(from, to);
            var result = scores.Select(s => new {
                s.EmployeeID,
                s.UserName,
                s.Department,
                s.CompanyID,
                s.Local,
                Part1 = s.Part1 ?? "not pass",
                Part2 = s.Part2 ?? "not pass",
                s.Part1Timestamp,
                s.Part2Timestamp
            });
            return Json(result, JsonRequestBehavior.AllowGet);
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
        [ValidateAntiForgeryToken]
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
        [ValidateAntiForgeryToken]
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
        [ValidateAntiForgeryToken]
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

        // ── BULK ACTIONS ─────────────────────────────────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult BulkAction(string action, List<string> empIDs)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            if (empIDs == null || !empIDs.Any())
                return Json(new { success = false, message = "No employees selected." });

            int done = 0;
            var errors = new List<string>();
            try
            {
                foreach (var id in empIDs)
                {
                    try
                    {
                        switch (action)
                        {
                            case "enable": DbHelper.SetEmployeeActive(id, "1"); done++; break;
                            case "disable": DbHelper.SetEmployeeActive(id, "0"); done++; break;
                            case "delete": DbHelper.DeleteEmployee(id); done++; break;
                            case "grant": DbHelper.SetEmployeeAccess(id, "1"); done++; break;
                            case "revoke": DbHelper.SetEmployeeAccess(id, "0"); done++; break;
                        }
                    }
                    catch (Exception ex) { errors.Add($"{id}: {ex.Message}"); }
                }
                return Json(new { success = true, done, errors });
            }
            catch (Exception ex) { return Json(new { success = false, message = ex.Message }); }
        }

        // ── BULK IMPORT ──────────────────────────────────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ImportEmployees(List<EmployeeFormModel> employees)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            if (employees == null || !employees.Any())
                return Json(new { success = false, message = "No data received." });

            int added = 0, updated = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var emp in employees)
            {
                if (string.IsNullOrWhiteSpace(emp.EmployeeID) || string.IsNullOrWhiteSpace(emp.UserName))
                { skipped++; continue; }
                try
                {
                    // Set defaults for missing fields
                    emp.Active = emp.Active ?? "1";
                    emp.Access = emp.Access ?? "1";
                    emp.SuperUser = emp.SuperUser ?? "0";
                    emp.Local = emp.Local ?? "1";

                    if (!DbHelper.EmployeeExists(emp.EmployeeID)) { DbHelper.InsertEmployee(emp); added++; }
                    else { DbHelper.UpdateEmployee(emp); updated++; }
                }
                catch (Exception ex) { errors.Add($"{emp.EmployeeID}: {ex.Message}"); }
            }
            return Json(new { success = true, added, updated, skipped, errors });
        }

        // ── CHECK DUPLICATE IC ───────────────────────────────────────────────
        [HttpGet]
        public JsonResult CheckIC(string ic, string excludeEmpID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            var existing = DbHelper.FindEmployeeByIC(ic, excludeEmpID);
            return Json(new { duplicate = existing != null, existing }, JsonRequestBehavior.AllowGet);
        }
    }
}