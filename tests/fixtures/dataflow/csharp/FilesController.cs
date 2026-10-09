using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.IO;

public class FilesController : Controller
{
    private readonly Storage storage = new Storage();

    public IActionResult Read()
    {
        string name = Request.Query["name"];
        return Content(System.IO.File.ReadAllText("/srv/" + name));  // EXPECT path-traversal direct
    }

    public IActionResult Run([FromQuery] string cmd)
    {
        storage.Execute(cmd);
        storage.RunTool(cmd);  // EXPECT command-injection cross-file
        return Ok();
    }

    public IActionResult Page([FromQuery] string n)
    {
        int page = int.Parse(n);
        Process.Start("report", page.ToString());
        return Ok();
    }
}

public class ReportsController : Controller
{
    private System.Data.SqlClient.SqlConnection connection;

    public IActionResult Find([FromQuery] string name)
    {
        IDbConnection db = connection;
        db.Query<Report>("SELECT * FROM reports WHERE name = '" + name + "'");  // EXPECT sql-injection direct
        return Ok();
    }
}
