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
                FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id AND Active='1' AND (IsArchived=0 OR IsArchived IS NULL)";
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
                FROM [dbo].[empMaster_lists] WHERE Active='1' AND (IsArchived=0 OR IsArchived IS NULL) ORDER BY UserName ASC";
            var list = new List<Employee>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapEmployee(r));
            return list;
        }

        // GetAllEmployeesAdmin moved below DeleteEmployee section

        public static bool EmployeeExists(string employeeId)
        {
            const string sql = "SELECT TOP 1 1 FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@Id", employeeId); using (var r = cmd.ExecuteReader()) return r.Read(); }
        }

        public static void InsertEmployee(EmployeeFormModel m)
        {
            const string sql = @"INSERT INTO [dbo].[empMaster_lists](EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Active,Local,Access,IsArchived)
                VALUES(@EmpID,@Name,@IC,@Dept,@Company,@Super,@Active,@Local,@Access,0)";
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

        public static void SetEmployeeActive(string empID, string value)
        {
            using (var con = Open())
            using (var cmd = Cmd("UPDATE [dbo].[empMaster_lists] SET Active=@Val WHERE EmployeeID=@Id", con))
            { cmd.Parameters.AddWithValue("@Val", value); cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        public static void SetEmployeeAccess(string empID, string value)
        {
            using (var con = Open())
            using (var cmd = Cmd("UPDATE [dbo].[empMaster_lists] SET Access=@Val WHERE EmployeeID=@Id", con))
            { cmd.Parameters.AddWithValue("@Val", value); cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        public static Employee FindEmployeeByIC(string ic, string excludeEmpID)
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] WHERE EmployeeIC=@IC AND (@Excl IS NULL OR EmployeeID<>@Excl)";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@IC", ic ?? "");
                cmd.Parameters.AddWithValue("@Excl", string.IsNullOrEmpty(excludeEmpID) ? (object)DBNull.Value : excludeEmpID);
                using (var r = cmd.ExecuteReader()) return r.Read() ? MapEmployee(r) : null;
            }
        }

        // Archive (soft delete) - sets IsArchived=1, disables login
        public static void ArchiveEmployee(string empID, string archivedByID)
        {
            const string sql = @"UPDATE [dbo].[empMaster_lists]
                SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By, Active='0', Access='0'
                WHERE EmployeeID=@Id";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@By", archivedByID ?? ""); cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        // Restore from archive
        public static void RestoreEmployee(string empID)
        {
            const string sql = @"UPDATE [dbo].[empMaster_lists]
                SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL, Active='1', Access='1'
                WHERE EmployeeID=@Id";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            { cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        // Hard delete (only for super-admin use)
        public static void HardDeleteEmployee(string empID)
        {
            using (var con = Open())
            using (var cmd = Cmd("DELETE FROM [dbo].[empMaster_lists] WHERE EmployeeID=@Id", con))
            { cmd.Parameters.AddWithValue("@Id", empID); cmd.ExecuteNonQuery(); }
        }

        // Get all archived employees
        public static List<Employee> GetArchivedEmployees()
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active,
                CONVERT(NVARCHAR(50),ArchivedAt,120) AS ArchivedAt, ArchivedBy
                FROM [dbo].[empMaster_lists] WHERE IsArchived=1 ORDER BY ArchivedAt DESC";
            var list = new List<Employee>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader())
                while (r.Read())
                {
                    var emp = MapEmployee(r);
                    emp.ArchivedAt = r["ArchivedAt"] != DBNull.Value ? r["ArchivedAt"].ToString() : null;
                    emp.ArchivedBy = r["ArchivedBy"] != DBNull.Value ? r["ArchivedBy"].ToString() : null;
                    list.Add(emp);
                }
            return list;
        }

        // Exclude archived from all normal queries - patch active queries to also filter IsArchived
        public static List<Employee> GetAllEmployeesAdmin()
        {
            const string sql = @"SELECT EmployeeID,UserName,EmployeeIC,Department,CompanyID,SuperUser,Access,Local,Active
                FROM [dbo].[empMaster_lists] WHERE (IsArchived=0 OR IsArchived IS NULL) ORDER BY UserName ASC";
            var list = new List<Employee>();
            using (var con = Open()) using (var cmd = Cmd(sql, con)) using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add(MapEmployee(r));
            return list;
        }

        // ── AUDIT LOG ────────────────────────────────────────────────────────
        public static void WriteLog(string actorID, string actorName, string actorRole,
            string action, string targetID, string targetName, string detail,
            string ipAddress, string result = "SUCCESS")
        {
            const string sql = @"INSERT INTO [dbo].[auditLog]
                (LogTime,ActorID,ActorName,ActorRole,Action,TargetID,TargetName,Detail,IPAddress,Result)
                VALUES(GETDATE(),@AID,@AName,@ARole,@Action,@TID,@TName,@Detail,@IP,@Result)";
            try
            {
                using (var con = Open()) using (var cmd = Cmd(sql, con))
                {
                    cmd.Parameters.AddWithValue("@AID", actorID ?? "");
                    cmd.Parameters.AddWithValue("@AName", actorName ?? "");
                    cmd.Parameters.AddWithValue("@ARole", actorRole ?? "");
                    cmd.Parameters.AddWithValue("@Action", action ?? "");
                    cmd.Parameters.AddWithValue("@TID", string.IsNullOrEmpty(targetID) ? (object)DBNull.Value : targetID);
                    cmd.Parameters.AddWithValue("@TName", string.IsNullOrEmpty(targetName) ? (object)DBNull.Value : targetName);
                    cmd.Parameters.AddWithValue("@Detail", string.IsNullOrEmpty(detail) ? (object)DBNull.Value : detail);
                    cmd.Parameters.AddWithValue("@IP", string.IsNullOrEmpty(ipAddress) ? (object)DBNull.Value : ipAddress);
                    cmd.Parameters.AddWithValue("@Result", result ?? "SUCCESS");
                    cmd.ExecuteNonQuery();
                }
            }
            catch { /* Logging must never crash the app */ }
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
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partOne_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
                ) a ON e.EmployeeID=a.EmployeeID AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partTwo_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
                ) b ON e.EmployeeID=b.EmployeeID AND b.rn=1
                WHERE e.EmployeeID=@EmpID AND e.UserName=@UN
                AND (e.IsArchived=0 OR e.IsArchived IS NULL) AND e.Active='1'";
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
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partOne_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
                ) a ON e.EmployeeID=a.EmployeeID AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn FROM partTwo_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
                ) b ON e.EmployeeID=b.EmployeeID AND b.rn=1
                WHERE e.Active='1' AND (e.IsArchived=0 OR e.IsArchived IS NULL) ORDER BY e.UserName ASC";
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
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part1,Timestamp AS Part1Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM partOne_scores WHERE Timestamp >= @From AND Timestamp < @To AND (IsArchived=0 OR IsArchived IS NULL)
                ) a ON e.EmployeeID=a.EmployeeID AND a.rn=1
                LEFT JOIN(SELECT EmployeeID,ScoreStatus AS Part2,Timestamp AS Part2Ts,
                    ROW_NUMBER() OVER(PARTITION BY EmployeeID ORDER BY Timestamp DESC) rn
                    FROM partTwo_scores WHERE Timestamp >= @From AND Timestamp < @To AND (IsArchived=0 OR IsArchived IS NULL)
                ) b ON e.EmployeeID=b.EmployeeID AND b.rn=1
                WHERE e.Active='1' AND (e.IsArchived=0 OR e.IsArchived IS NULL) ORDER BY e.UserName ASC";
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
            // NOTE: Join on EmployeeID only - UserName may change if employee is renamed
            const string sql = "SELECT TOP 1 1 FROM partOne_scores WHERE EmployeeID=@EmpID AND TrainingYear=@Year AND ScoreStatus='pass'";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID);
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

        public static TrainingProgressInfo GetTrainingProgress(string empID, int part, int year)
        {
            const string sql = @"SELECT SlideIndex, SlideId, Lang,
                CONVERT(nvarchar(20), LastUpdated, 105) + ' ' + CONVERT(nvarchar(8), LastUpdated, 108) AS LastUpdated
                FROM training_progress WHERE EmployeeID=@EmpID AND Part=@Part AND TrainingYear=@Year";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID);
                cmd.Parameters.AddWithValue("@Part", part);
                cmd.Parameters.AddWithValue("@Year", year);
                using (var r = cmd.ExecuteReader())
                    if (r.Read()) return new TrainingProgressInfo
                    {
                        SlideIndex = (int)r["SlideIndex"],
                        SlideId = r["SlideId"] != DBNull.Value ? r["SlideId"].ToString() : null,
                        Lang = r["Lang"] != DBNull.Value ? r["Lang"].ToString() : "english",
                        LastUpdated = r["LastUpdated"] != DBNull.Value ? r["LastUpdated"].ToString() : null
                    };
            }
            return new TrainingProgressInfo { SlideIndex = 0, Lang = "english" };
        }

        public static void SaveTrainingProgress(string empID, int part, int year, string lang, int slideIndex, string slideId)
        {
            if (slideIndex <= 0)
            {
                using (var con = Open())
                using (var cmd = Cmd("DELETE FROM training_progress WHERE EmployeeID=@EmpID AND Part=@Part AND TrainingYear=@Year", con))
                { cmd.Parameters.AddWithValue("@EmpID", empID); cmd.Parameters.AddWithValue("@Part", part); cmd.Parameters.AddWithValue("@Year", year); cmd.ExecuteNonQuery(); }
                return;
            }
            const string upsert = @"IF EXISTS (SELECT 1 FROM training_progress WHERE EmployeeID=@EmpID AND Part=@Part AND TrainingYear=@Year)
                UPDATE training_progress SET SlideIndex=@Slide, SlideId=@SlideId, Lang=@Lang, LastUpdated=GETDATE()
                WHERE EmployeeID=@EmpID AND Part=@Part AND TrainingYear=@Year
            ELSE
                INSERT INTO training_progress(EmployeeID,Part,TrainingYear,Lang,SlideIndex,SlideId,LastUpdated)
                VALUES(@EmpID,@Part,@Year,@Lang,@Slide,@SlideId,GETDATE())";
            using (var con = Open()) using (var cmd = Cmd(upsert, con))
            {
                cmd.Parameters.AddWithValue("@EmpID", empID);
                cmd.Parameters.AddWithValue("@Part", part);
                cmd.Parameters.AddWithValue("@Year", year);
                cmd.Parameters.AddWithValue("@Lang", lang ?? "english");
                cmd.Parameters.AddWithValue("@Slide", slideIndex);
                cmd.Parameters.AddWithValue("@SlideId", string.IsNullOrEmpty(slideId) ? (object)DBNull.Value : slideId);
                cmd.ExecuteNonQuery();
            }
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

        // ── SCORE ARCHIVING ──────────────────────────────────────────────────

        /// <summary>Archive scores for a specific employee (both Part1 and Part2).</summary>
        public static int ArchiveScoresByEmployee(string empID, string archivedByID)
        {
            int count = 0;
            using (var con = Open())
            {
                using (var cmd = Cmd(@"UPDATE partOne_scores SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By
                    WHERE EmployeeID=@Id AND (IsArchived=0 OR IsArchived IS NULL)", con))
                { cmd.Parameters.AddWithValue("@By", archivedByID ?? ""); cmd.Parameters.AddWithValue("@Id", empID); count += cmd.ExecuteNonQuery(); }
                using (var cmd = Cmd(@"UPDATE partTwo_scores SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By
                    WHERE EmployeeID=@Id AND (IsArchived=0 OR IsArchived IS NULL)", con))
                { cmd.Parameters.AddWithValue("@By", archivedByID ?? ""); cmd.Parameters.AddWithValue("@Id", empID); count += cmd.ExecuteNonQuery(); }
            }
            return count;
        }

        /// <summary>Archive ALL scores for a given training year (both tables).</summary>
        public static int ArchiveScoresByYear(int year, string archivedByID)
        {
            int count = 0;
            using (var con = Open())
            {
                using (var cmd = Cmd(@"UPDATE partOne_scores SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By
                    WHERE TrainingYear=@Year AND (IsArchived=0 OR IsArchived IS NULL)", con))
                { cmd.Parameters.AddWithValue("@By", archivedByID ?? ""); cmd.Parameters.AddWithValue("@Year", year); count += cmd.ExecuteNonQuery(); }
                using (var cmd = Cmd(@"UPDATE partTwo_scores SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By
                    WHERE TrainingYear=@Year AND (IsArchived=0 OR IsArchived IS NULL)", con))
                { cmd.Parameters.AddWithValue("@By", archivedByID ?? ""); cmd.Parameters.AddWithValue("@Year", year); count += cmd.ExecuteNonQuery(); }
            }
            return count;
        }

        /// <summary>Archive selected score records by their IDs.</summary>
        public static int ArchiveScoreRecords(string table, List<int> ids, string archivedByID)
        {
            if (table != "partOne_scores" && table != "partTwo_scores") throw new ArgumentException("Invalid table.");
            if (ids == null || ids.Count == 0) return 0;
            var paramNames = new List<string>();
            for (int i = 0; i < ids.Count; i++) paramNames.Add("@id" + i);
            string sql = $"UPDATE {table} SET IsArchived=1, ArchivedAt=GETDATE(), ArchivedBy=@By WHERE ID IN ({string.Join(",", paramNames)}) AND (IsArchived=0 OR IsArchived IS NULL)";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                cmd.Parameters.AddWithValue("@By", archivedByID ?? "");
                for (int i = 0; i < ids.Count; i++) cmd.Parameters.AddWithValue("@id" + i, ids[i]);
                return cmd.ExecuteNonQuery();
            }
        }

        /// <summary>Restore archived scores for a specific employee.</summary>
        public static int RestoreScoresByEmployee(string empID)
        {
            int count = 0;
            using (var con = Open())
            {
                using (var cmd = Cmd(@"UPDATE partOne_scores SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL
                    WHERE EmployeeID=@Id AND IsArchived=1", con))
                { cmd.Parameters.AddWithValue("@Id", empID); count += cmd.ExecuteNonQuery(); }
                using (var cmd = Cmd(@"UPDATE partTwo_scores SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL
                    WHERE EmployeeID=@Id AND IsArchived=1", con))
                { cmd.Parameters.AddWithValue("@Id", empID); count += cmd.ExecuteNonQuery(); }
            }
            return count;
        }

        /// <summary>Restore all archived scores for a given training year.</summary>
        public static int RestoreScoresByYear(int year)
        {
            int count = 0;
            using (var con = Open())
            {
                using (var cmd = Cmd(@"UPDATE partOne_scores SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL
                    WHERE TrainingYear=@Year AND IsArchived=1", con))
                { cmd.Parameters.AddWithValue("@Year", year); count += cmd.ExecuteNonQuery(); }
                using (var cmd = Cmd(@"UPDATE partTwo_scores SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL
                    WHERE TrainingYear=@Year AND IsArchived=1", con))
                { cmd.Parameters.AddWithValue("@Year", year); count += cmd.ExecuteNonQuery(); }
            }
            return count;
        }

        /// <summary>Restore selected score records by their IDs.</summary>
        public static int RestoreScoreRecords(string table, List<int> ids)
        {
            if (table != "partOne_scores" && table != "partTwo_scores") throw new ArgumentException("Invalid table.");
            if (ids == null || ids.Count == 0) return 0;
            var paramNames = new List<string>();
            for (int i = 0; i < ids.Count; i++) paramNames.Add("@id" + i);
            string sql = $"UPDATE {table} SET IsArchived=0, ArchivedAt=NULL, ArchivedBy=NULL WHERE ID IN ({string.Join(",", paramNames)}) AND IsArchived=1";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                for (int i = 0; i < ids.Count; i++) cmd.Parameters.AddWithValue("@id" + i, ids[i]);
                return cmd.ExecuteNonQuery();
            }
        }

        /// <summary>Get all archived score records with employee info for display.</summary>
        public static List<ArchivedScoreRecord> GetArchivedScores(int? filterYear = null, string filterEmpID = null)
        {
            string sql = @"SELECT 'Part1' AS Part, s.ID, s.EmployeeID, s.UserName, s.ScorePercentage, s.ScoreStatus,
                    s.TrainingYear, s.Timestamp, CONVERT(NVARCHAR(50),s.ArchivedAt,120) AS ArchivedAt, s.ArchivedBy,
                    ISNULL(e.Department,'') AS Department, ISNULL(e.CompanyID,'') AS CompanyID
                FROM partOne_scores s
                LEFT JOIN empMaster_lists e ON s.EmployeeID=e.EmployeeID
                WHERE s.IsArchived=1";
            if (filterYear.HasValue) sql += " AND s.TrainingYear=@Year";
            if (!string.IsNullOrEmpty(filterEmpID)) sql += " AND s.EmployeeID=@EmpID";
            sql += @" UNION ALL
                SELECT 'Part2' AS Part, s.ID, s.EmployeeID, s.UserName, s.ScorePercentage, s.ScoreStatus,
                    s.TrainingYear, s.Timestamp, CONVERT(NVARCHAR(50),s.ArchivedAt,120) AS ArchivedAt, s.ArchivedBy,
                    ISNULL(e.Department,'') AS Department, ISNULL(e.CompanyID,'') AS CompanyID
                FROM partTwo_scores s
                LEFT JOIN empMaster_lists e ON s.EmployeeID=e.EmployeeID
                WHERE s.IsArchived=1";
            if (filterYear.HasValue) sql += " AND s.TrainingYear=@Year";
            if (!string.IsNullOrEmpty(filterEmpID)) sql += " AND s.EmployeeID=@EmpID";
            sql += " ORDER BY ArchivedAt DESC, EmployeeID, Part";

            var list = new List<ArchivedScoreRecord>();
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            {
                if (filterYear.HasValue) cmd.Parameters.AddWithValue("@Year", filterYear.Value);
                if (!string.IsNullOrEmpty(filterEmpID)) cmd.Parameters.AddWithValue("@EmpID", filterEmpID);
                using (var r = cmd.ExecuteReader())
                    while (r.Read()) list.Add(new ArchivedScoreRecord
                    {
                        Part = r["Part"].ToString(),
                        ID = (int)r["ID"],
                        EmployeeID = r["EmployeeID"].ToString(),
                        UserName = r["UserName"].ToString(),
                        ScorePercentage = r["ScorePercentage"].ToString(),
                        ScoreStatus = r["ScoreStatus"].ToString(),
                        TrainingYear = r["TrainingYear"] != DBNull.Value ? (int)r["TrainingYear"] : 0,
                        Timestamp = r["Timestamp"] != DBNull.Value ? r["Timestamp"].ToString() : null,
                        ArchivedAt = r["ArchivedAt"] != DBNull.Value ? r["ArchivedAt"].ToString() : null,
                        ArchivedBy = r["ArchivedBy"] != DBNull.Value ? r["ArchivedBy"].ToString() : null,
                        Department = r["Department"].ToString(),
                        CompanyID = r["CompanyID"].ToString()
                    });
            }
            return list;
        }

        /// <summary>Get distinct training years that have archived scores.</summary>
        public static List<int> GetArchivedScoreYears()
        {
            var list = new List<int>();
            string sql = @"SELECT DISTINCT TrainingYear FROM (
                SELECT TrainingYear FROM partOne_scores WHERE IsArchived=1
                UNION SELECT TrainingYear FROM partTwo_scores WHERE IsArchived=1
            ) x WHERE TrainingYear IS NOT NULL ORDER BY TrainingYear DESC";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add((int)r[0]);
            return list;
        }

        /// <summary>Get distinct training years that have active (non-archived) scores.</summary>
        public static List<int> GetActiveScoreYears()
        {
            var list = new List<int>();
            string sql = @"SELECT DISTINCT TrainingYear FROM (
                SELECT TrainingYear FROM partOne_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
                UNION SELECT TrainingYear FROM partTwo_scores WHERE (IsArchived=0 OR IsArchived IS NULL)
            ) x WHERE TrainingYear IS NOT NULL ORDER BY TrainingYear DESC";
            using (var con = Open()) using (var cmd = Cmd(sql, con))
            using (var r = cmd.ExecuteReader()) while (r.Read()) list.Add((int)r[0]);
            return list;
        }

    }

    public static class DataReaderExtensions
    {
        public static bool HasColumn(this SqlDataReader r, string col)
        { for (int i = 0; i < r.FieldCount; i++) if (r.GetName(i).Equals(col, StringComparison.OrdinalIgnoreCase)) return true; return false; }
    }
}