using System;
using System.Web.Mvc;
using ABC_WebApp.Helpers;
using ABC_WebApp.Models;

namespace ABC_WebApp.Controllers
{
    public class TrainingController : Controller
    {
        // ── GET /Training/Part1 ──────────────────────────────────────────────
        public ActionResult Part1()
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");

            return View();
        }

        // ── GET /Training/Part2 ──────────────────────────────────────────────
        public ActionResult Part2()
        {
            if (!SessionHelper.IsLoggedIn)
                return RedirectToAction("Login", "Auth");

            // Server-side gate: must have passed Part 1 this year
            if (!DbHelper.IsPart1PassedThisYear(SessionHelper.EmployeeID, SessionHelper.UserName))
            {
                TempData["ErrorMessage"] = "You must complete and PASS Part 1 before accessing Part 2.";
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        // ── POST /Training/SubmitPart1  (AJAX JSON) ──────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult SubmitPart1(TrainingSubmitModel model)
        {
            if (!SessionHelper.IsLoggedIn)
                return Json(new { success = false, message = "Session expired. Please log in again." });

            if (!ModelState.IsValid)
                return Json(new { success = false, message = "Invalid submission data." });

            // Prevent score injection: only the logged-in user can submit their own score
            if (model.EmpID != SessionHelper.EmployeeID || model.UserName != SessionHelper.UserName)
                return Json(new { success = false, message = "Unauthorised submission." });

            try
            {
                DbHelper.SaveScore("ABC_partOne_scores", model);
                return Json(new
                {
                    success   = true,
                    message   = "Part 1 results saved successfully!",
                    timestamp = DateTime.Now.ToString("dd MMM yyyy HH:mm")
                });
            }
            catch (Exception)
            {
                return Json(new { success = false, message = "Failed to save. Please try again or contact IT Support." });
            }
        }

        // ── GET /Training/GetProgress ────────────────────────────────────────
        public JsonResult GetProgress(int part)
        {
            if (!SessionHelper.IsLoggedIn || (part != 1 && part != 2))
                return Json(new { slideIndex = 0, slideId = (string)null, lang = "english", lastUpdated = (string)null }, JsonRequestBehavior.AllowGet);
            var prog = DbHelper.GetTrainingProgress(SessionHelper.EmployeeID, part, DateTime.Now.Year);
            return Json(new { slideIndex = prog.SlideIndex, slideId = prog.SlideId, lang = prog.Lang, lastUpdated = prog.LastUpdated }, JsonRequestBehavior.AllowGet);
        }

        // ── POST /Training/SaveProgress ──────────────────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult SaveProgress(int part, int slideIndex, string slideId, string lang)
        {
            if (!SessionHelper.IsLoggedIn || (part != 1 && part != 2))
                return Json(new { success = false });
            try
            {
                DbHelper.SaveTrainingProgress(SessionHelper.EmployeeID, part, DateTime.Now.Year, lang ?? "english", slideIndex, slideId ?? "");
                return Json(new { success = true });
            }
            catch { return Json(new { success = false }); }
        }

        // ── POST /Training/SubmitPart2  (AJAX JSON) ──────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult SubmitPart2(TrainingSubmitModel model)
        {
            if (!SessionHelper.IsLoggedIn)
                return Json(new { success = false, message = "Session expired. Please log in again." });

            if (!ModelState.IsValid)
                return Json(new { success = false, message = "Invalid submission data." });

            if (model.EmpID != SessionHelper.EmployeeID || model.UserName != SessionHelper.UserName)
                return Json(new { success = false, message = "Unauthorised submission." });

            // Double-check Part 1 gate on the server
            if (!DbHelper.IsPart1PassedThisYear(model.EmpID, model.UserName))
                return Json(new { success = false, message = "Part 1 must be passed before submitting Part 2." });

            try
            {
                DbHelper.SaveScore("ABC_partTwo_scores", model);
                return Json(new
                {
                    success   = true,
                    message   = "Part 2 results saved successfully!",
                    timestamp = DateTime.Now.ToString("dd MMM yyyy HH:mm")
                });
            }
            catch (Exception)
            {
                return Json(new { success = false, message = "Failed to save. Please try again or contact IT Support." });
            }
        }
    }
}
