using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using ABC_WebApp.Models;

namespace ABC_WebApp.Helpers
{
    /// <summary>
    /// Centralised data-access layer. No API calls – direct SQL to the database.
    /// </summary>
    public static class DbHelper
    {
        private static string ConnStr =>
            ConfigurationManager.ConnectionStrings["EmployeeDatabase"].ConnectionString;

        // ── Employee ─────────────────────────────────────────────────────────

        public static Employee GetEmployee(string employeeId)
        {
            const string sql = @"
                SELECT EmployeeID, UserName, EmployeeIC, Department,
                       CompanyID, SuperUser, Access, Local
                FROM   [dbo].[empMaster_lists]
                WHERE  EmployeeID = @Id AND Active = '1'";

            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@Id", employeeId);
                using (var r = cmd.ExecuteReader())
                    return r.Read() ? MapEmployee(r) : null;
            }
        }

        public static List<Employee> GetAllEmployees()
        {
            const string sql = @"
                SELECT EmployeeID, UserName, EmployeeIC, Department,
                       CompanyID, SuperUser, Access, Local
                FROM   [dbo].[empMaster_lists]
                WHERE  Active = '1'
                ORDER  BY UserName ASC";

            var list = new List<Employee>();
            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            using (var r = cmd.ExecuteReader())
                while (r.Read()) list.Add(MapEmployee(r));
            return list;
        }

        // ── Scores ───────────────────────────────────────────────────────────

        /// <summary>Returns the latest Part1 / Part2 score row for one employee.</summary>
        public static EmployeeScore GetEmployeeScore(string empID, string userName)
        {
            const string sql = @"
                SELECT e.EmployeeID, e.UserName, e.Department, e.CompanyID, e.Local,
                       COALESCE(a.Part1, 'not pass')    AS Part1,
                       COALESCE(a.Part1Ts,  NULL)       AS Part1Timestamp,
                       COALESCE(b.Part2, 'not pass')    AS Part2,
                       COALESCE(b.Part2Ts,  NULL)       AS Part2Timestamp
                FROM   empMaster_lists e
                LEFT JOIN (
                    SELECT EmployeeID, UserName,
                           ScoreStatus AS Part1, Timestamp AS Part1Ts,
                           ROW_NUMBER() OVER (PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM   partOne_scores
                ) a ON e.EmployeeID = a.EmployeeID AND e.UserName = a.UserName AND a.rn = 1
                LEFT JOIN (
                    SELECT EmployeeID, UserName,
                           ScoreStatus AS Part2, Timestamp AS Part2Ts,
                           ROW_NUMBER() OVER (PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM   partTwo_scores
                ) b ON e.EmployeeID = b.EmployeeID AND e.UserName = b.UserName AND b.rn = 1
                WHERE  e.EmployeeID = @EmpID AND e.UserName = @UN AND e.Active = '1'";

            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID);
                cmd.Parameters.AddWithValue("@UN",    userName);
                using (var r = cmd.ExecuteReader())
                    return r.Read() ? MapScore(r) : null;
            }
        }

        /// <summary>Returns all employees with their latest Part1 / Part2 scores.</summary>
        public static List<EmployeeScore> GetAllScores()
        {
            const string sql = @"
                SELECT e.EmployeeID, e.UserName, e.Department, e.CompanyID, e.Local,
                       COALESCE(a.Part1, 'not pass')    AS Part1,
                       COALESCE(a.Part1Ts,  NULL)       AS Part1Timestamp,
                       COALESCE(b.Part2, 'not pass')    AS Part2,
                       COALESCE(b.Part2Ts,  NULL)       AS Part2Timestamp
                FROM   empMaster_lists e
                LEFT JOIN (
                    SELECT EmployeeID, UserName,
                           ScoreStatus AS Part1, Timestamp AS Part1Ts,
                           ROW_NUMBER() OVER (PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM   partOne_scores
                ) a ON e.EmployeeID = a.EmployeeID AND e.UserName = a.UserName AND a.rn = 1
                LEFT JOIN (
                    SELECT EmployeeID, UserName,
                           ScoreStatus AS Part2, Timestamp AS Part2Ts,
                           ROW_NUMBER() OVER (PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM   partTwo_scores
                ) b ON e.EmployeeID = b.EmployeeID AND e.UserName = b.UserName AND b.rn = 1
                WHERE  e.Active = '1'
                ORDER  BY e.UserName ASC";

            var list = new List<EmployeeScore>();
            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            using (var r = cmd.ExecuteReader())
                while (r.Read()) list.Add(MapScore(r));
            return list;
        }

        public static void SaveScore(string tableName, TrainingSubmitModel m)
        {
            // Whitelist to prevent SQL injection via table name
            if (tableName != "partOne_scores" && tableName != "partTwo_scores")
                throw new ArgumentException("Invalid table name.");

            string sql = $@"INSERT INTO {tableName}
                            (EmployeeID, UserName, ScorePercentage, ScoreStatus, TrainingYear, Timestamp)
                            VALUES (@EmpID, @UN, @Score, @Status, @Year, @Ts)";

            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID",  m.EmpID);
                cmd.Parameters.AddWithValue("@UN",     m.UserName);
                cmd.Parameters.AddWithValue("@Score",  m.ScorePercentage);
                cmd.Parameters.AddWithValue("@Status", m.ScoreStatus);
                cmd.Parameters.AddWithValue("@Year",   DateTime.Now.Year);
                cmd.Parameters.AddWithValue("@Ts",     DateTime.Now);
                cmd.ExecuteNonQuery();
            }
        }

        /// <summary>Returns true if the employee has passed Part 1 in the current calendar year.</summary>
        public static bool IsPart1PassedThisYear(string empID, string userName)
        {
            const string sql = @"
                SELECT TOP 1 1
                FROM   partOne_scores
                WHERE  EmployeeID = @EmpID AND UserName = @UN
                   AND TrainingYear = @Year AND ScoreStatus = 'pass'";

            using (var con = Open())
            using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID);
                cmd.Parameters.AddWithValue("@UN",    userName);
                cmd.Parameters.AddWithValue("@Year",  DateTime.Now.Year);
                using (var r = cmd.ExecuteReader())
                    return r.Read();
            }
        }

        // ── Timestamp helpers ─────────────────────────────────────────────────

        public static bool IsPassedInYear(string status, string timestamp, int year)
        {
            if (string.IsNullOrEmpty(status) || string.IsNullOrEmpty(timestamp)) return false;
            if (!status.Equals("pass", StringComparison.OrdinalIgnoreCase)) return false;
            return ExtractYear(timestamp) == year;
        }

        public static int? ExtractYear(string timestamp)
        {
            if (string.IsNullOrEmpty(timestamp)) return null;
            try { return DateTime.Parse(timestamp.Split('.')[0]).Year; }
            catch { return null; }
        }

        // ── Private helpers ───────────────────────────────────────────────────

        private static SqlConnection Open()
        {
            var con = new SqlConnection(ConnStr);
            con.Open();
            return con;
        }

        private static SqlCommand Cmd(string sql, SqlConnection con) =>
            new SqlCommand(sql, con);

        private static Employee MapEmployee(SqlDataReader r) => new Employee
        {
            EmployeeID = r["EmployeeID"].ToString(),
            UserName   = r["UserName"].ToString(),
            EmployeeIC = r["EmployeeIC"].ToString(),
            Department = r["Department"].ToString(),
            CompanyID  = r["CompanyID"].ToString(),
            SuperUser  = r["SuperUser"].ToString(),
            Access     = r["Access"].ToString(),
            Local      = r.HasColumn("Local") && r["Local"] != DBNull.Value
                             ? r["Local"].ToString() : ""
        };

        private static EmployeeScore MapScore(SqlDataReader r) => new EmployeeScore
        {
            EmployeeID     = r["EmployeeID"].ToString(),
            UserName       = r["UserName"].ToString(),
            Department     = r["Department"].ToString(),
            CompanyID      = r["CompanyID"].ToString(),
            Local          = r["Local"] != DBNull.Value ? r["Local"].ToString() : "",
            Part1          = r["Part1"].ToString(),
            Part1Timestamp = r["Part1Timestamp"] != DBNull.Value ? r["Part1Timestamp"].ToString() : null,
            Part2          = r["Part2"].ToString(),
            Part2Timestamp = r["Part2Timestamp"] != DBNull.Value ? r["Part2Timestamp"].ToString() : null
        };
    }

    // Extension method so MapEmployee can check column existence safely
    public static class DataReaderExtensions
    {
        public static bool HasColumn(this SqlDataReader r, string col)
        {
            for (int i = 0; i < r.FieldCount; i++)
                if (r.GetName(i).Equals(col, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
