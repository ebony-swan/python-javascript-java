using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

namespace VulnApp;

// Shared in-memory SQLite, mirroring the other lab apps: users alice/bob (role
// user) + admin (role admin); notes id=2 and id=4 are private. A "keep-alive"
// connection is held open so the in-memory database survives between requests;
// each query opens its own connection to the shared cache.
public static class Db
{
    private const string ConnStr = "Data Source=file:vulndb?mode=memory&cache=shared";
    private static SqliteConnection _keepAlive;

    // Deliberately weak, unsalted password hash used across the lab.
    public static string Md5(string s)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    }

    public static void Init()
    {
        _keepAlive = new SqliteConnection(ConnStr);
        _keepAlive.Open();

        Exec(@"CREATE TABLE users(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 password TEXT NOT NULL,      -- unsalted MD5 hash (see crypto demo)
                 email TEXT,
                 role TEXT NOT NULL DEFAULT 'user',
                 ssn TEXT);
               CREATE TABLE notes(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 owner TEXT NOT NULL,
                 title TEXT,
                 body TEXT,                   -- rendered unescaped by the stored-XSS demo
                 private INTEGER NOT NULL DEFAULT 0);");

        ExecParams("INSERT INTO users(username,password,email,role,ssn) VALUES(@u,@p,@e,@r,@s)",
            ("@u", "alice"), ("@p", Md5("password1")), ("@e", "alice@example.com"), ("@r", "user"), ("@s", "111-11-1111"));
        ExecParams("INSERT INTO users(username,password,email,role,ssn) VALUES(@u,@p,@e,@r,@s)",
            ("@u", "bob"), ("@p", Md5("bobs-dog-2019")), ("@e", "bob@example.com"), ("@r", "user"), ("@s", "222-22-2222"));
        ExecParams("INSERT INTO users(username,password,email,role,ssn) VALUES(@u,@p,@e,@r,@s)",
            ("@u", "admin"), ("@p", Md5("admin123")), ("@e", "admin@example.com"), ("@r", "admin"), ("@s", "999-99-9999"));

        ExecParams("INSERT INTO notes(owner,title,body,private) VALUES(@o,@t,@b,@p)",
            ("@o", "alice"), ("@t", "Shopping list"), ("@b", "milk, eggs, bread"), ("@p", 0));
        ExecParams("INSERT INTO notes(owner,title,body,private) VALUES(@o,@t,@b,@p)",
            ("@o", "alice"), ("@t", "Bank PIN reminder"), ("@b", "PIN is 4821 (do not share)"), ("@p", 1));
        ExecParams("INSERT INTO notes(owner,title,body,private) VALUES(@o,@t,@b,@p)",
            ("@o", "bob"), ("@t", "Public note"), ("@b", "hello world"), ("@p", 0));
        ExecParams("INSERT INTO notes(owner,title,body,private) VALUES(@o,@t,@b,@p)",
            ("@o", "admin"), ("@t", "Ops runbook"), ("@b", "prod db password: hunter2"), ("@p", 1));
    }

    public static void Exec(string sql)
    {
        using var c = new SqliteConnection(ConnStr);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static void ExecParams(string sql, params (string, object)[] ps)
    {
        using var c = new SqliteConnection(ConnStr);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    // Runs a query and returns rows as dictionaries (the SQLi demos rely on the
    // column set changing at runtime, e.g. via UNION SELECT).
    public static List<Dictionary<string, object>> Query(string sql, params (string, object)[] ps)
    {
        using var c = new SqliteConnection(ConnStr);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        using var r = cmd.ExecuteReader();
        var rows = new List<Dictionary<string, object>>();
        while (r.Read())
        {
            var m = new Dictionary<string, object>();
            for (int i = 0; i < r.FieldCount; i++)
                m[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
            rows.Add(m);
        }
        return rows;
    }
}
