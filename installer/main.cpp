#include <iostream>
#include <windows.h>
#include <string>
#include <tuple>
#include <vector>
#include <wininet.h>
#include <fstream>

#pragma comment(lib, "wininet.lib")

std::string QQDonwload = "https://dldir1.qq.com/qqfile/qq/QQNT/b07cb1a5/QQ9.9.15.27597_x64.exe";

std::string getMidText(std::string str, std::string str1, std::string str2)
{
    std::string returnStr;
    int strIndex = str.find(str1);
    if (strIndex != -1)
    {
        strIndex = strIndex + str1.length();
        int endIndex = str.find(str2, strIndex);
        if (endIndex != -1)
        {
            returnStr = str.substr(strIndex, endIndex - strIndex);
            return returnStr;
        }
    }
    return returnStr;
}

bool HttpGet(const std::string &url, std::string &response)
{
    HINTERNET hInternet = InternetOpen("HTTPGET", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        std::cerr << "InternetOpen failed" << std::endl;
        return false;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, std::string(url.begin(), url.end()).c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect)
    {
        std::cerr << "InternetOpenUrl failed" << std::endl;
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0)
    {
        response.append(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return true;
}

bool DownloadFile(const std::string &url, const std::string &filePath)
{
    std::string response;
    if (!HttpGet(url, response))
    {
        return false;
    }

    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Failed to open file for writing" << std::endl;
        return false;
    }

    outFile.write(response.c_str(), response.size());
    outFile.close();
    return true;
}

std::string getNapCatVersionByPackageMirror()
{
    std::vector<std::string> napcatVersionPath = {
        "http://jsd.cdn.zzko.cn/gh/NapNeko/NapCatQQ@main/package.json",
        "http://fastly.jsdelivr.net/gh/NapNeko/NapCatQQ@main/package.json",
        "https://gcore.jsdelivr.net/gh/NapNeko/NapCatQQ@main/package.json",
        "https://cdn.jsdelivr.net/gh/NapNeko/NapCatQQ@main/package.json"};

    for (const auto &url : napcatVersionPath)
    {
        std::string response = "";
        if (HttpGet(url, response))
        {
            // 处理响应数据
            // std::cout << "Response from " << url << ": " << response << std::endl;
            return response;
        }
    }

    return "";
}

std::string getNapCatVersionByPackage()
{
    std::string res = getNapCatVersionByPackageMirror();
    if (res.empty())
    {
        return "";
    }
    return getMidText(res, "\"version\": \"", "\"");
}

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
    std::string response = "";
    // 开始请求HTTP http://nclatest.znin.net/ 解析Json
    if (HttpGet("http://nclatest.znin.net/", response))
    {
        // "html_url": "https://github.com/NapNeko/NapCatQQ/releases/tag/v2.3.5",
        //获取v2.3.5这种值
        return getMidText(response,"https://github.com/NapNeko/NapCatQQ/releases/tag/", "\"");
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
    return std::stoi(getMidText(packageData, "\"buildVersion\":", ","));
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
    return std::stoi(getMidText(packageData, "\"buildId\": \"", "\""));
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
        std::cout << "获取NapCat最新版本失败,尝试备用地址" << std::endl;
        NcVersion = "v" + getNapCatVersionByPackage();
    }
    if (NcVersion == "")
    {
        std::cout << "获取NapCat最新版本失败" << std::endl;
        system("pause");
        return -1;
    }
    std::cout << "NapCat最新版本:" << NcVersion << std::endl;
    std::string napcatDownloadUrl = "/https://github.com/NapNeko/NapCatQQ/releases/download/" + NcVersion + "/NapCat.Shell.zip";
    // 下载文件
    auto isDownloaded = DownloadFile("http://github.moeyy.xyz" + napcatDownloadUrl, "NapCat.Shell.zip");
    std::cout << "下载地址: " << "http://github.moeyy.xyz" << napcatDownloadUrl << std::endl;
    if (!isDownloaded)
    {
        std::cout << "下载NapCat失败" << std::endl;
        system("pause");
        return -1;
    }
    // 调用powershell的 Expand-Archive -Path "./NapCat.Shell.zip" -DestinationPath "./NapCatQQ/" -Force 解压
    system("powershell Expand-Archive -Path \"./NapCat.Shell.zip\" -DestinationPath \"./NapCatQQ/\" -Force");
    system("cls");
    std::cout << "欢迎使用哦~~ 双击启动在启动本程序NapCatQQ目录下 launcher.bat 或者 launcher-win10.bat 即可" << std::endl;
    system("pause");
    return 0;
}
