cd ..\src\ServiceStack.Authentication.Marten
dotnet pack --configuration Release

cd bin\Release

..\..\..\..\nuget\nuget.exe push *.nupkg -Source https://www.nuget.org/api/v2/package

cd ..\..\
cd ..\..\nuget