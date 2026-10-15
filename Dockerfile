FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source
COPY global.json Directory.Build.props ./
COPY src/AuthService/AuthService.csproj src/AuthService/packages.lock.json src/AuthService/
RUN dotnet restore src/AuthService/AuthService.csproj --locked-mode
COPY src/ src/
RUN dotnet publish src/AuthService/AuthService.csproj -c Release --no-restore -o /app

FROM build AS test
COPY tests/ tests/
RUN dotnet restore tests/AuthService.Tests/AuthService.Tests.csproj --locked-mode
ENTRYPOINT ["dotnet", "test", "tests/AuthService.Tests/AuthService.Tests.csproj", "--no-restore", "--logger", "console;verbosity=normal"]

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
USER app
ENV ASPNETCORE_HTTP_PORTS=8080
ENTRYPOINT ["dotnet", "AuthService.dll"]
