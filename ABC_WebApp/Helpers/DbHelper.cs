using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using ABC_WebApp.Models;

namespace ABC_WebApp.Helpers
{
    public static class DbHelper
    {
        private static string ConnStr =>
            ConfigurationManager.ConnectionStrings["EmployeeDatabase"].ConnectionString;

        public static Employee GetEmployee(string employeeId)
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id AND Active='1'";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@Id", employeeId); using (var r = cmd.ExecuteReader()) return r.Read() ? MapEmployee(r) : null; }
        }

        public static Employee GetEmployeeAdmin(string employeeId)
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@Id", employeeId); using (var r = cmd.ExecuteReader()) return r.Read() ? MapEmployee(r) : null; }
        }

        public static List<Employee> GetAllEmployees()
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] WHERE Active='1' ORDER BY UserName ASC";
            var list = new List<Employee>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapEmployee(r));
            return list;
        }

        public static List<Employee> GetAllEmployeesAdmin()
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] ORDER BY UserName ASC";
            var list = new List<Employee>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapEmployee(r));
            return list;
        }

        public static bool EmployeeExists(string employeeId)
        {
            const string sql = "SELECT TOP 1 1 FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@Id", employeeId); using (var r = cmd.ExecuteReader()) return r.Read(); }
        }

        public static void InsertEmployee(EmployeeFormModel m)
        {
            const string sql = @"INSERT INTO [dbo].[empMaster_lists](EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Active,Local,Access)
                VALUES(@EmpID,@Name,@IC,@Dept,@Company,@Super,@Active,@Local,@Access)";
            using (var con = Open()) using (var cmd = Cmd(sql, con)) { SetEmpParams(cmd, m); cmd.ExecuteNonQuery(); }
        }

        public static void UpdateEmployee(EmployeeFormModel m)
        {
            const string sql = @"UPDATE [dbo].[empMaster_lists] SET UserName=@Name,EmployeeIC=@IC,Department=@Dept,
                CompanyID=@Company,SuperUser=@Super,Active=@Active,Local=@Local,Access=@Access WHERE EmployeeID=@EmpID";
            using (var con = Open()) using (var cmd = Cmd(sql, con)) { SetEmpParams(cmd, m); cmd.ExecuteNonQuery(); }
        }

        public static string ToggleEmployeeActive(string empID)
        {
            string current;
            using (var con = Open())
            {
                using (var cmd = Cmd("SELECT Active FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id", con))
                { cmd.Parameters.AddWithValue("@Id", empID); current = cmd.ExecuteScalar()?.ToString() ?? "0"; }
                string nv = current == "1" ? "0" : "1";
                using (var cmd = Cmd("UPDATE [dbo].[empMaster_lists] SET Active=@Val WHERE EmployeeID=@Id", con))
                { cmd.Parameters.AddWithValue("@Val", nv); cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
                return nv;
            }
        }

        public static void DeleteEmployee(string empID)
        {
            using (var con = Open())
            using (var cmd = Cmd("DELETE FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id", con))
            { cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        private static void SetEmpParams(SqlCommand cmd, EmployeeFormModel m)
        {
            cmd.Parameters.AddWithValue("@EmpID", m.EmployeeID ?? "");
            cmd.Parameters.AddWithValue("@Name", m.UserName ?? "");
            cmd.Parameters.AddWithValue("@IC", m.EmployeeIC ?? "");
            cmd.Parameters.AddWithValue("@Dept", m.Department ?? "");
            cmd.Parameters.AddWithValue("@Company", m.CompanyID ?? "");
            cmd.Parameters.AddWithValue("@Super", m.SuperUser ?? "0");
            cmd.Parameters.AddWithValue("@Active", m.Active ?? "1");
            cmd.Parameters.AddWithValue("@Local", m.Local ?? "1");
            cmd.Parameters.AddWithValue("@Access", m.Access ?? "1");
        }

        public static EmployeeScore GetEmployeeScore(string empID, string userName)
        {
            const string sql = @"SELECT e.EmployeeID,e.UserName,e.Department,e.CompanyID,e.Local,
                COALESCE(a.Part1,'not pass') AS Part1, COALESCE(a.Part1Ts,NULL) AS Part1Timestamp,
                COALESCE(b.Part2,'not pass') AS Part2, COALESCE(b.Part2Ts,NULL) AS Part2Timestamp
                FROM empMaster_lists e
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partOne_scores
                ) a ON e.EmployeeID=a.EmployeeID AND e.UserName=a.UserName AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partTwo_scores
                ) b ON e.EmployeeID=b.EmployeeID AND e.UserName=b.UserName AND b.rn=1
                WHERE e.EmployeeID=@EmpID AND e.UserName=@UN AND e.Active='1'";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID); cmd.Parameters.AddWithValue("@UN", userName);
                using (var r = cmd.ExecuteReader()) return r.Read() ? MapScore(r) : null;
            }
        }

        public static List<EmployeeScore> GetAllScores()
        {
            const string sql = @"SELECT e.EmployeeID,e.UserName,e.Department,e.CompanyID,e.Local,
                COALESCE(a.Part1,'not pass') AS Part1, COALESCE(a.Part1Ts,NULL) AS Part1Timestamp,
                COALESCE(b.Part2,'not pass') AS Part2, COALESCE(b.Part2Ts,NULL) AS Part2Timestamp
                FROM empMaster_lists e
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partOne_scores
                ) a ON e.EmployeeID=a.EmployeeID AND e.UserName=a.UserName AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partTwo_scores
                ) b ON e.EmployeeID=b.EmployeeID AND e.UserName=b.UserName AND b.rn=1
                WHERE e.Active='1' ORDER BY e.UserName ASC";
            var list = new List<EmployeeScore>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapScore(r));
            return list;
        }

        /// <summary>
        /// Returns all employees with their latest Part1/Part2 score within a date range (inclusive).
        /// Employees with no score in the range show 'not pass'.
        /// </summary>
        public static List<EmployeeScore> GetAllScoresForDateRange(DateTime from, DateTime to)
        {
            // Add 1 day to 'to' so we include the full end date (up to 23:59:59)
            DateTime toInclusive = to.AddDays(1);
            const string sql = @"SELECT e.EmployeeID,e.UserName,e.Department,e.CompanyID,e.Local,
                COALESCE(a.Part1,'not pass') AS Part1, COALESCE(a.Part1Ts,NULL) AS Part1Timestamp,
                COALESCE(b.Part2,'not pass') AS Part2, COALESCE(b.Part2Ts,NULL) AS Part2Timestamp
                FROM empMaster_lists e
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM partOne_scores WHERE Timestamp >= @From AND Timestamp < @To
                ) a ON e.EmployeeID=a.EmployeeID AND e.UserName=a.UserName AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,UserName,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM partTwo_scores WHERE Timestamp >= @From AND Timestamp < @To
                ) b ON e.EmployeeID=b.EmployeeID AND e.UserName=b.UserName AND b.rn=1
                WHERE e.Active='1' ORDER BY e.UserName ASC";
            var list = new List<EmployeeScore>();
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@From", from);
                cmd.Parameters.AddWithValue("@To", toInclusive);
                using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapScore(r));
            }
            return list;
        }

        public static void SaveScore(string tableName, TrainingSubmitModel m)
        {
            if (tableName != "partOne_scores" && tableName != "partTwo_scores") throw new ArgumentException("Invalid table.");
            string sql = $"INSERT INTO {tableName}(EmployeeID,UserName,ScorePercentage,ScoreStatus,TrainingYear,Timestamp) VALUES(@EmpID,@UN,@Score,@Status,@Year,@Ts)";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", m.EmpID); cmd.Parameters.AddWithValue("@UN", m.UserName);
                cmd.Parameters.AddWithValue("@Score", m.ScorePercentage); cmd.Parameters.AddWithValue("@Status", m.ScoreStatus);
                cmd.Parameters.AddWithValue("@Year", DateTime.Now.Year); cmd.Parameters.AddWithValue("@Ts", DateTime.Now);
                cmd.ExecuteNonQuery();
            }
        }

        public static bool IsPart1PassedThisYear(string empID, string userName)
        {
            const string sql = "SELECT TOP 1 1 FROM partOne_scores WHERE EmployeeID=@EmpID AND UserName=@UN AND TrainingYear=@Year AND ScoreStatus='pass'";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID); cmd.Parameters.AddWithValue("@UN", userName);
                cmd.Parameters.AddWithValue("@Year", DateTime.Now.Year); using (var r = cmd.ExecuteReader()) return r.Read();
            }
        }

        public static bool IsPassedInYear(string status, string timestamp, int year)
        {
            if (string.IsNullOrEmpty(status) || !status.Equals("pass", StringComparison.OrdinalIgnoreCase)) return false;
            if (string.IsNullOrEmpty(timestamp)) return false;
            return ExtractYear(timestamp) == year;
        }

        public static int? ExtractYear(string timestamp)
        {
            if (string.IsNullOrEmpty(timestamp)) return null;
            try { return DateTime.Parse(timestamp.Split('.')[0]).Year; } catch { return null; }
        }

        private static SqlConnection Open() { var c = new SqlConnection(ConnStr); c.Open(); return c; }
        private static SqlCommand Cmd(string sql, SqlConnection con) => new SqlCommand(sql, con);

        private static Employee MapEmployee(SqlDataReader r) => new Employee
        {
            EmployeeID = r["EmployeeID"].ToString(),
            UserName = r["UserName"].ToString(),
            EmployeeIC = r["EmployeeIC"].ToString(),
            Department = r["Department"].ToString(),
            CompanyID = r["CompanyID"].ToString(),
            SuperUser = r["SuperUser"].ToString(),
            Access = r["Access"].ToString(),
            Active = r["Active"].ToString(),
            Local = r["Local"] != DBNull.Value ? r["Local"].ToString() : "1"
        };

        private static EmployeeScore MapScore(SqlDataReader r) => new EmployeeScore
        {
            EmployeeID = r["EmployeeID"].ToString(),
            UserName = r["UserName"].ToString(),
            Department = r["Department"].ToString(),
            CompanyID = r["CompanyID"].ToString(),
            Local = r["Local"] != DBNull.Value ? r["Local"].ToString() : "1",
            Part1 = r["Part1"].ToString(),
            Part2 = r["Part2"].ToString(),
            Part1Timestamp = r["Part1Timestamp"] != DBNull.Value ? r["Part1Timestamp"].ToString() : null,
            Part2Timestamp = r["Part2Timestamp"] != DBNull.Value ? r["Part2Timestamp"].ToString() : null
        };
    }

    public static class DataReaderExtensions
    {
        public static bool HasColumn(this SqlDataReader r, string col)
        { for (int i = 0; i < r.FieldCount; i++) if (r.GetName(i).Equals(col, StringComparison.OrdinalIgnoreCase)) return true; return false; }
    }
}
