using System.Text.Json.Nodes;
using ReproIt.Sdk;

static OfficialManagedProject BindInstalledPackage(JsonObject project)
{
    return new OfficialManagedProject(
        project,
        "source.example/acme/commerce",
        "0123456789abcdef0123456789abcdef01234567");
}

_ = (Func<JsonObject, OfficialManagedProject>)BindInstalledPackage;
_ = typeof(ReproItCapture);
