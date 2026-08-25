using ReproIt.Sdk;

static AutomaticProjectOptions InstalledPackageOptions()
{
    return new AutomaticProjectOptions
    {
        BuildRepositoryId = "source.example/acme/commerce",
        ProjectToml = "[project]",
        SourceRevision = "0123456789abcdef0123456789abcdef01234567",
    };
}

_ = (Func<AutomaticProjectOptions>)InstalledPackageOptions;
_ = typeof(AutomaticProject);
