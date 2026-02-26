using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;

namespace ABC_WebApp.Models
{
    // ══════════════════════════════════════════════════════════════
    //  EF Database Context
    // ══════════════════════════════════════════════════════════════
    public class EmployeeContext : DbContext
    {
        public EmployeeContext() : base("name=EmployeeDatabase") { }
    }

    // ══════════════════════════════════════════════════════════════
    //  Domain / DB models  (column names must match the DB)
    // ══════════════════════════════════════════════════════════════
    public class Employee
    {
        public string EmployeeID { get; set; }
        public string UserName   { get; set; }
        public string EmployeeIC { get; set; }
        public string Department { get; set; }
        public string CompanyID  { get; set; }
        public string SuperUser  { get; set; }
        public string Access     { get; set; }
        public string Local      { get; set; }
    }

    public class EmployeeScore
    {
        public string EmployeeID     { get; set; }
        public string UserName       { get; set; }
        public string Department     { get; set; }
        public string CompanyID      { get; set; }
        public string Local          { get; set; }
        public string Part1          { get; set; }
        public string Part2          { get; set; }
        public string Part1Timestamp { get; set; }
        public string Part2Timestamp { get; set; }
    }

    public class LockEmployee
    {
        public string EmployeeID { get; set; }
    }

    // ══════════════════════════════════════════════════════════════
    //  View Models
    // ══════════════════════════════════════════════════════════════
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Employee ID is required.")]
        [Display(Name = "Employee ID")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    public class DashboardViewModel
    {
        public Employee CurrentEmployee { get; set; }
        public string   Part1Status     { get; set; }   // "pass" | "not pass"
        public string   Part2Status     { get; set; }
        public bool     IsPart2Unlocked { get; set; }
        public int      CurrentYear     { get; set; }
        public bool     IsSuperUser     { get; set; }
        public string   ErrorMessage    { get; set; }
    }

    public class TrainingSubmitModel
    {
        [Required] public string EmpID           { get; set; }
        [Required] public string UserName        { get; set; }
        [Required] public string ScorePercentage { get; set; }
        [Required] public string ScoreStatus     { get; set; }
    }

    public class AdminDashboardViewModel
    {
        public List<EmployeeScore> Scores        { get; set; }
        public int  TotalEmployees               { get; set; }
        public int  PassedPart1                  { get; set; }
        public int  PassedPart2                  { get; set; }
        public int  NotPassedPart1               { get; set; }
        public int  NotPassedPart2               { get; set; }
        public int  CurrentYear                  { get; set; }
    }
}
