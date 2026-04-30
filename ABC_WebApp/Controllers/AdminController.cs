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
                TotalSuperUsers = employees.Count(e => e.SuperUser == "1"),
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

            DateTime from;
            DateTime to;
            if (!DateTime.TryParseExact(dateFrom, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out from))
                from = new DateTime(DateTime.Now.Year, 1, 1);

            if (!DateTime.TryParseExact(dateTo, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out to))
                to = DateTime.Now.Date;

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
        public JsonResult SaveEmployee(EmployeeFormModel model, string reason)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            if (string.IsNullOrWhiteSpace(model.EmployeeID) || string.IsNullOrWhiteSpace(model.UserName))
                return Json(new { success = false, message = "Employee ID and Name are required." });
            try
            {
                bool isNew = !DbHelper.EmployeeExists(model.EmployeeID);
                string detail = null;
                if (!isNew)
                {
                    var existing = DbHelper.GetEmployeeAdmin(model.EmployeeID);
                    bool settingInactive = model.Active == "0" && existing?.Active == "1";
                    bool settingRestricted = model.Access == "0" && existing?.Access == "1";
                    if ((settingInactive || settingRestricted) && string.IsNullOrWhiteSpace(reason))
                        return Json(new { success = false, message = "A reason is required when setting Inactive or Restricted access." });
                    if (!string.IsNullOrWhiteSpace(reason)) detail = reason.Trim();
                }
                if (isNew) DbHelper.InsertEmployee(model);
                else DbHelper.UpdateEmployee(model);
                string action = isNew ? "ADD_EMPLOYEE" : "EDIT_EMPLOYEE";
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    action, model.EmployeeID, model.UserName, detail, GetIP(), "SUCCESS");
                return Json(new { success = true, message = isNew ? "Employee added." : "Employee updated.", isNew });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "SAVE_EMPLOYEE_FAIL", model.EmployeeID, model.UserName, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
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
                string logAction = s == "1" ? "ENABLE_EMPLOYEE" : "DISABLE_EMPLOYEE";
                var empInfo = DbHelper.GetEmployeeAdmin(empID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    logAction, empID, empInfo?.UserName, null, GetIP(), "SUCCESS");
                return Json(new { success = true, status = s });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "TOGGLE_FAIL", empID, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ToggleAccess(string empID, string reason)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                var emp = DbHelper.GetEmployeeAdmin(empID);
                if (emp == null) return Json(new { success = false, message = "Employee not found." });
                string newAccess = emp.Access == "1" ? "0" : "1";
                if (newAccess == "0" && string.IsNullOrWhiteSpace(reason))
                    return Json(new { success = false, message = "A reason is required to restrict portal access." });
                DbHelper.SetEmployeeAccess(empID, newAccess);
                string logAction = newAccess == "1" ? "GRANT_ACCESS" : "REVOKE_ACCESS";
                string detail = newAccess == "0" ? reason?.Trim() : null;
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    logAction, empID, emp.UserName, detail, GetIP(), "SUCCESS");
                return Json(new { success = true, status = newAccess });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "TOGGLE_ACCESS_FAIL", empID, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ArchiveEmployee(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                var emp = DbHelper.GetEmployeeAdmin(empID);
                string empName = emp?.UserName ?? empID;
                DbHelper.ArchiveEmployee(empID, SessionHelper.EmployeeID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_EMPLOYEE", empID, empName, null, GetIP(), "SUCCESS");
                return Json(new { success = true, message = "Employee archived." });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_EMPLOYEE", empID, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult RestoreEmployee(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                var emp = DbHelper.GetEmployeeAdmin(empID);
                string empName = emp?.UserName ?? empID;
                DbHelper.RestoreEmployee(empID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "RESTORE_EMPLOYEE", empID, empName, null, GetIP(), "SUCCESS");
                return Json(new { success = true, message = "Employee restored." });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "RESTORE_EMPLOYEE", empID, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public JsonResult GetArchivedEmployees()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            return Json(DbHelper.GetArchivedEmployees(), JsonRequestBehavior.AllowGet);
        }

        // ── BULK ACTIONS ─────────────────────────────────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult BulkAction(string action, List<string> empIDs, string reason)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            if (empIDs == null || !empIDs.Any())
                return Json(new { success = false, message = "No employees selected." });
            if ((action == "disable" || action == "revoke") && string.IsNullOrWhiteSpace(reason))
                return Json(new { success = false, message = "A reason is required for this action." });

            string detail = reason?.Trim();
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
                            case "archive": DbHelper.ArchiveEmployee(id, SessionHelper.EmployeeID); done++; break;
                            case "grant": DbHelper.SetEmployeeAccess(id, "1"); done++; break;
                            case "revoke": DbHelper.SetEmployeeAccess(id, "0"); done++; break;
                        }
                    }
                    catch (Exception ex) { errors.Add($"{id}: {ex.Message}"); }
                }
                if (done > 0 && (action == "disable" || action == "revoke"))
                {
                    string logAction = action == "disable" ? "BULK_DISABLE" : "BULK_REVOKE_ACCESS";
                    string summary = $"{done} employee(s) affected. Reason: {detail}";
                    DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                        logAction, null, null, summary, GetIP(), "SUCCESS");
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

        // ── SCORE ARCHIVING ────────────────────────────────────────────────────

        [HttpGet]
        public JsonResult GetArchivedScores(int? year, string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            return Json(DbHelper.GetArchivedScores(year, empID), JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        public JsonResult GetArchivedScoreYears()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            return Json(DbHelper.GetArchivedScoreYears(), JsonRequestBehavior.AllowGet);
        }

        [HttpGet]
        public JsonResult GetActiveScoreYears()
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { error = "Unauthorised" }, JsonRequestBehavior.AllowGet);
            return Json(DbHelper.GetActiveScoreYears(), JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ArchiveScoresByEmployee(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.ArchiveScoresByEmployee(empID, SessionHelper.EmployeeID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_SCORES_EMP", empID, null, $"{count} records archived", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} score records archived." });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_SCORES_EMP", empID, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ArchiveScoresByYear(int year)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.ArchiveScoresByYear(year, SessionHelper.EmployeeID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_SCORES_YEAR", null, null, $"Year {year}: {count} records archived", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} score records archived for year {year}." });
            }
            catch (Exception ex)
            {
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_SCORES_YEAR", null, null, ex.Message, GetIP(), "FAIL");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult ArchiveScoreRecords(string table, List<int> ids)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.ArchiveScoreRecords(table, ids, SessionHelper.EmployeeID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "ARCHIVE_SCORE_RECORDS", null, null, $"{table}: {count} records", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} records archived." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult RestoreScoresByEmployee(string empID)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.RestoreScoresByEmployee(empID);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "RESTORE_SCORES_EMP", empID, null, $"{count} records restored", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} score records restored." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult RestoreScoresByYear(int year)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.RestoreScoresByYear(year);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "RESTORE_SCORES_YEAR", null, null, $"Year {year}: {count} records restored", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} records restored for year {year}." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult RestoreScoreRecords(string table, List<int> ids)
        {
            if (!SessionHelper.IsLoggedIn || !SessionHelper.IsAdmin)
                return Json(new { success = false, message = "Unauthorised" });
            try
            {
                int count = DbHelper.RestoreScoreRecords(table, ids);
                DbHelper.WriteLog(SessionHelper.EmployeeID, SessionHelper.UserName, "Admin",
                    "RESTORE_SCORE_RECORDS", null, null, $"{table}: {count} records", GetIP(), "SUCCESS");
                return Json(new { success = true, count, message = $"{count} records restored." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        // ── HELPERS ───────────────────────────────────────────────────────────
        private string GetIP()
        {
            string ip = Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            if (string.IsNullOrEmpty(ip)) ip = Request.ServerVariables["REMOTE_ADDR"];
            return ip?.Split(',')[0].Trim() ?? "unknown";
        }

        // ── LOG WRAPPERS for SaveEmployee / ToggleActive / BulkAction ─────────
        // (Already in those methods above - but we need to add logging there too)
    }
}