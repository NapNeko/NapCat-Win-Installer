#include <iostream>
#include <string>
#include <tuple>
#include "./meojson/json.hpp"
#include "./httplib.h"

std::string QQDonwload = "https://dldir1.qq.com/qqfile/qq/QQNT/b07cb1a5/QQ9.9.15.27597_x64.exe";

std::tuple<bool, std::string> getQQInstalled()
{
    // 读取注册表 HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\QQ
    LONG QQUnInstallTableResult;
    LONG QQUnInstallResult;
    HKEY QQUnInstallData;
    std::string QQPath;
    char szUninstallString[1024]; // 缓存区1024
    DWORD dwSize = sizeof(szUninstallString);
    QQUnInstallTableResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\QQ", 0, KEY_READ, &QQUnInstallData);
    if (QQUnInstallTableResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, "");
    }
    QQUnInstallResult = RegQueryValueEx(QQUnInstallData, "UninstallString", NULL, NULL, (LPBYTE)szUninstallString, &dwSize);
    if (QQUnInstallResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, "");
    }
    QQPath = szUninstallString;
    QQPath = QQPath.substr(0, QQPath.find_last_of("\\")); // 截取路径
    return std::make_tuple(true, QQPath);
}
std::string getNapCatVersion()
{
    // 开始请求HTTP http://nclatest.znin.net/ 解析Json
    httplib::Client nclatestHost("http://nclatest.znin.net");
    if (auto res = nclatestHost.Get("/"))
    {
        // std::cout << res->status << std::endl;
        // std::cout << res->get_header_value("Content-Type") << std::endl;
        // std::cout << res->body << std::endl;
        if (res->status != 200)
        {
            return "";
        }
        auto ret = json::parse(res->body);
        if (!ret)
        {
            return "";
        }
        json::value &value = *ret;
        // std::cout << (std::string)value["tag_name"] << std::endl;
        return (std::string)value["tag_name"];
    }
    return "";
}
int getQQVersionByPackage(std::string QQPath)
{
    // 组装目录 .\resources\app\package.json
    std::string QQVersionPath = QQPath + "\\resources\\app\\package.json";
    // 判断文件是否存在
    std::ifstream QQVersionFile(QQVersionPath);
    if (!QQVersionFile)
    {
        return 0;
    }
    std::string packageData = "";
    std::string line;
    while (std::getline(QQVersionFile, line))
    {
        packageData += line;
    }
    QQVersionFile.close();
    // 解析Json
    auto ret = json::parse(packageData);
    if (!ret)
    {
        return 0;
    }
    json::value &value = *ret;
    return std::stoi((std::string)value["buildVersion"]);
}
int getQQVersionByConfig(std::string QQPath)
{
    // 组装目录 .\config\config.json
    std::string QQVersionPath = QQPath + "\\resources\\app\\versions\\config.json";
    // 判断文件是否存在
    std::ifstream QQVersionFile(QQVersionPath);
    if (!QQVersionFile)
    {
        return 0;
    }
    std::string packageData = "";
    std::string line;
    while (std::getline(QQVersionFile, line))
    {
        packageData += line;
    }
    QQVersionFile.close();
    // 解析Json
    auto ret = json::parse(packageData);
    if (!ret)
    {
        return 0;
    }
    json::value &value = *ret;
    return std::stoi((std::string)value["buildId"]);
}
int main()
{
    bool isQQInstalled;
    std::string QQPath;
    std::tie(isQQInstalled, QQPath) = getQQInstalled();
    int targetQQVersion = 27597;
    system("chcp 65001");
    std::cout << "检测QQ是否安装" << std::endl;
    if (isQQInstalled)
    {
        std::cout << "QQ已安装,安装路径为:" << QQPath << std::endl;
    }
    else
    {
        std::cout << "QQ未安装,开始下载QQ..." << std::endl;
        ShellExecute(NULL, "open", QQDonwload.c_str(), NULL, NULL, SW_SHOWNORMAL);
        system("pause");
        return -1;
    }
    int tempBuildId = getQQVersionByConfig(QQPath);
    if (tempBuildId == 0)
    {
        tempBuildId = getQQVersionByPackage(QQPath);
    }
    if (tempBuildId == 0)
    {
        std::cout << "获取QQ版本失败" << std::endl;
        system("pause");
        return -1;
    }
    std::cout << "QQ版本:" << tempBuildId << std::endl;
    if (tempBuildId >= targetQQVersion)
    {
        std::cout << "QQ版本正确" << std::endl;
    }
    else
    {
        std::cout << "QQ版本错误,开始下载QQ..." << std::endl;
        ShellExecute(NULL, "open", QQDonwload.c_str(), NULL, NULL, SW_SHOWNORMAL);
        system("pause");
        return -1;
    }
    std::string NcVersion = getNapCatVersion();
    if (NcVersion == "")
    {
        std::cout << "获取NapCat最新版本失败" << std::endl;
        system("pause");
        return -1;
    }
    std::cout << "NapCat最新版本:" << NcVersion << std::endl;
    std::string napcatDownloadUrl = "/https://github.com/NapNeko/NapCatQQ/releases/download/" + NcVersion + "/NapCat.Shell.zip";
    // 下载文件
    httplib::Client downloadHost("http://github.moeyy.xyz");
    std::cout << "下载地址: " << "http://github.moeyy.xyz" << napcatDownloadUrl << std::endl;
    if (auto res = downloadHost.Get(napcatDownloadUrl.c_str()))
    {
        if (res->status != 200)
        {
            std::cout << "下载NapCat失败" << res->status << std::endl;
            system("pause");
            return -1;
        }
        std::ofstream out("NapCat.Shell.zip", std::ios::binary);
        out.write(res->body.c_str(), res->body.size());
        out.close();
    }
    else
    {
        std::cout << "下载NapCat失败" << std::endl;
        system("pause");
        return -1;
    }
    // 调用powershell的 Expand-Archive -Path "./NapCat.Shell.zip" -DestinationPath "./NapCatQQ/" -Force 解压
    system("powershell Expand-Archive -Path \"./NapCat.Shell.zip\" -DestinationPath \"./NapCatQQ/\" -Force");
    // 移动./NapCatQQ/dbghelp.dll 到QQPath
    std::string dbghelpPath = QQPath + "\\dbghelp.dll";
    // 获取当前目录
    char currentPath[1024];
    GetCurrentDirectory(1024, currentPath);
    std::string dbghelpNapCatPath = currentPath;
    dbghelpNapCatPath += "\\NapCatQQ\\dbghelp.dll";
    std::cout << "Target: dbghelp.dll:" << dbghelpPath << std::endl;
    std::cout << "Source: dbghelp.dll:" << dbghelpNapCatPath << std::endl;
    // 判断是否被占用
    system("taskkill /f /im QQ.exe");
    // 判断原来的dbghelp.dll是否存在
    if (std::ifstream(dbghelpPath))
    {
        // 删除原来的dbghelp.dll
        std::remove(dbghelpPath.c_str());
    }
    // 移动dbghelp.dll
    std::rename(dbghelpNapCatPath.c_str(), dbghelpPath.c_str());
    // 弹出提示框是否启动NapCat
    int ret = MessageBox(NULL, TEXT("是否启动NapCat?"), TEXT("NapCat"), MB_YESNO);
    // 启动powershell 设置Set-ExecutionPolicy Unrestricted
    system("powershell Set-ExecutionPolicy Unrestricted");
    if (ret == IDYES)
    {
        // 新建分离进程启动 BootWay05.ps1
        system("start powershell -noexit -file ./NapCatQQ/BootWay05.ps1");
    }
    std::cout << "欢迎使用哦~~ 下次启动在启动本程序NapCatQQ目录下 BootWay05.ps1即可" << std::endl;
    system("pause");
    return 0;
}
