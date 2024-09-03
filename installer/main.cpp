#include <windows.h>
#include <iostream>
#include <string>
#include <tuple>
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

int main()
{
	bool isQQInstalled;
	std::string QQPath;
	std::tie(isQQInstalled, QQPath) = getQQInstalled();
	system("chcp 65001 > null");
	std::cout << "检测QQ是否安装" << std::endl;
	if (isQQInstalled)
	{
		std::cout << "QQ已安装，安装路径为：" << QQPath << std::endl;
	}
	else
	{
		std::cout << "QQ未安装，开始下载QQ" << std::endl;
		ShellExecute(NULL, "open", QQDonwload.c_str(), NULL, NULL, SW_SHOWNORMAL);
		return -1;
	}

	return 0;
}
