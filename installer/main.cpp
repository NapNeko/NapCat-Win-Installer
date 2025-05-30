#include <iostream>
#include <windows.h>
#include <string>
#include <tuple>
#include <vector>
#include <wininet.h>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "wininet.lib")

// 控制台文本颜色常量
constexpr int COLOR_INFO = 11;    // 浅青色
constexpr int COLOR_SUCCESS = 10; // 亮绿色
constexpr int COLOR_ERROR = 12;   // 亮红色
constexpr int COLOR_WARNING = 14; // 黄色
constexpr int COLOR_NORMAL = 7;   // 白色

const std::wstring QQ_DOWNLOAD_URL = L"https://dldir1.qq.com/qqfile/qq/QQNT/f56b3dec/QQ9.9.19.35469_x64.exe";
const std::wstring QQ_EXE_PATH = L"QQ.exe";
const std::wstring QQ_EXTRACT_DIR = L"NapCat.35469.Framework";
const std::wstring NAPCAT_ZIP_PATH = L"NapCat.Framework.zip";
const std::wstring NAPCAT_EXTRACT_DIR = L"NapCat.35469.Framework\\versions\\9.9.19-35469\\resources\\app\\LiteLoader\\plugins\\NapCat";
const std::wstring LiteLoader_DIR = L"NapCat.35469.Framework\\versions\\9.9.19-35469\\resources\\app\\LiteLoader";
const std::wstring PACKAGE_JSON_PATH = L"NapCat.35469.Framework\\versions\\9.9.19-35469\\resources\\app\\package.json";

// 编码转换函数：将 UTF-16 (wstring) 转换为 ANSI (string)
std::string WideToAnsi(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);

    return strTo;
}

// 编码转换函数：将 ANSI (string) 转换为 UTF-16 (wstring)
std::wstring AnsiToWide(const std::string &str)
{
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);

    return wstrTo;
}

// 编码转换函数：将 UTF-16 (wstring) 转换为 UTF-8 (string)
std::string WideToUtf8(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);

    return strTo;
}

// 编码转换函数：将 UTF-8 (string) 转换为 UTF-16 (wstring)
std::wstring Utf8ToWide(const std::string &str)
{
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);

    return wstrTo;
}

// 设置控制台文字颜色
void setConsoleColor(int color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// 打印带颜色的信息
void printInfo(const std::wstring &message)
{
    setConsoleColor(COLOR_INFO);
    std::wcout << L"[信息] " << message << std::endl;
    setConsoleColor(COLOR_NORMAL);
}

void printSuccess(const std::wstring &message)
{
    setConsoleColor(COLOR_SUCCESS);
    std::wcout << L"[成功] " << message << std::endl;
    setConsoleColor(COLOR_NORMAL);
}

void printError(const std::wstring &message)
{
    setConsoleColor(COLOR_ERROR);
    std::wcout << L"[错误] " << message << std::endl;
    setConsoleColor(COLOR_NORMAL);
}

void printWarning(const std::wstring &message)
{
    setConsoleColor(COLOR_WARNING);
    std::wcout << L"[警告] " << message << std::endl;
    setConsoleColor(COLOR_NORMAL);
}

bool modifyPackageJson()
{
    printInfo(L"准备修改package.json文件...");

    // 检查文件是否存在
    if (!std::filesystem::exists(PACKAGE_JSON_PATH))
    {
        printError(L"找不到package.json文件: " + PACKAGE_JSON_PATH);
        return false;
    }

    // 读取文件内容
    std::ifstream inFile(PACKAGE_JSON_PATH);
    if (!inFile)
    {
        printError(L"无法打开package.json文件");
        return false;
    }

    std::string content_utf8((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // 转换为宽字符便于处理
    std::wstring content = Utf8ToWide(content_utf8);

    // 创建备份
    std::wstring backupPath = PACKAGE_JSON_PATH + L".bak";
    std::ofstream backupFile(backupPath, std::ios::binary);
    if (!backupFile)
    {
        printWarning(L"无法创建备份文件，将继续不创建备份");
    }
    else
    {
        backupFile << content_utf8;
        backupFile.close();
        printInfo(L"已创建package.json备份");
    }

    // 替换目标字符串
    const std::wstring oldPath = L"./application.asar/app_launcher/index.js";
    const std::wstring newPath = L"./LiteLoader";

    // 查找并替换
    size_t pos = content.find(oldPath);
    if (pos != std::wstring::npos)
    {
        content.replace(pos, oldPath.length(), newPath);

        // 转换回UTF-8并写回文件
        std::string modified_utf8 = WideToUtf8(content);
        std::ofstream outFile(PACKAGE_JSON_PATH, std::ios::binary);
        if (!outFile)
        {
            printError(L"无法写入修改后的package.json文件");
            return false;
        }

        outFile << modified_utf8;
        outFile.close();
        printSuccess(L"已成功将启动脚本路径替换为 " + newPath);
        return true;
    }
    else
    {
        printWarning(L"在package.json中未找到需要替换的路径，可能格式已变更");
        return false;
    }
}

// 检查文件是否存在并有效的辅助函数
bool isFileExistAndValid(const std::wstring &filePath, size_t minSizeBytes = 1024)
{
    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec))
    {
        return false;
    }

    // 检查文件大小是否大于最小有效大小
    auto fileSize = std::filesystem::file_size(filePath, ec);
    if (ec)
    { // 如果出现错误
        return false;
    }
    return fileSize >= minSizeBytes;
}

// 带进度显示的文件下载函数，支持301/302重定向
bool DownloadFile(const std::wstring &url, const std::wstring &filePath)
{
    // 转换为ANSI以便WinInet API使用
    std::string urlAnsi = WideToAnsi(url);

    HINTERNET hInternet = InternetOpenA("DOWNLOADER", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        printError(L"InternetOpen 调用失败");
        return false;
    }

    // 添加 INTERNET_FLAG_NO_AUTO_REDIRECT 标志以便我们可以手动处理重定向
    HINTERNET hConnect = InternetOpenUrlA(hInternet, urlAnsi.c_str(), NULL, 0, 
        INTERNET_FLAG_RELOAD, 0);
    if (!hConnect)
    {
        printError(L"InternetOpenUrl 调用失败");
        InternetCloseHandle(hInternet);
        return false;
    }

    // 检查是否需要重定向
    DWORD statusCode = 0;
    DWORD dataSize = sizeof(statusCode);
    DWORD index = 0;
    if (HttpQueryInfoA(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, 
                      &statusCode, &dataSize, &index))
    {
        // 处理301/302重定向
        if (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308)
        {
            printInfo(L"检测到HTTP重定向(" + std::to_wstring(statusCode) + L")");
            
            // 获取Location头
            char locationBuffer[1024] = {0};
            dataSize = sizeof(locationBuffer);
            index = 0;
            if (HttpQueryInfoA(hConnect, HTTP_QUERY_LOCATION, locationBuffer, &dataSize, &index))
            {
                // 关闭当前连接
                InternetCloseHandle(hConnect);
                
                std::string newUrlAnsi(locationBuffer);
                std::wstring newUrl = AnsiToWide(newUrlAnsi);
                printInfo(L"重定向到: " + newUrl);
                
                // 打开新的URL
                hConnect = InternetOpenUrlA(hInternet, newUrlAnsi.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
                if (!hConnect)
                {
                    printError(L"重定向后连接失败");
                    InternetCloseHandle(hInternet);
                    return false;
                }
            }
            else
            {
                printWarning(L"无法获取重定向URL，尝试继续下载");
            }
        }
    }

    // 获取文件大小
    DWORD contentLength = 0;
    dataSize = sizeof(contentLength);
    index = 0;
    if (!HttpQueryInfo(hConnect, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &dataSize, &index))
    {
        printWarning(L"无法获取文件大小，将只显示已下载量");
        contentLength = 0; // 如果无法获取大小，设为0
    }

    // 使用宽字符版本的文件操作
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile)
    {
        printError(L"无法打开文件进行写入: " + filePath);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    // 其余下载代码保持不变
    char buffer[8192];
    DWORD bytesRead;
    DWORD totalBytesRead = 0;
    int progressPercent = 0;
    int lastProgressPercent = -1;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0)
    {
        outFile.write(buffer, bytesRead);
        totalBytesRead += bytesRead;

        // 显示进度
        if (contentLength > 0)
        {
            progressPercent = static_cast<int>((static_cast<double>(totalBytesRead) / contentLength) * 100);
            if (progressPercent != lastProgressPercent)
            {
                setConsoleColor(COLOR_INFO);
                std::wcout << L"\r下载进度: [";

                // 进度条
                int barWidth = 30;
                int pos = barWidth * progressPercent / 100;
                for (int i = 0; i < barWidth; ++i)
                {
                    if (i < pos)
                        std::wcout << L"=";
                    else if (i == pos)
                        std::wcout << L">";
                    else
                        std::wcout << L" ";
                }

                std::wcout << L"] " << progressPercent << L"% ("
                           << (totalBytesRead / 1024 / 1024) << L"MB/"
                           << (contentLength / 1024 / 1024) << L"MB)" << std::flush;
                lastProgressPercent = progressPercent;
            }
        }
        else
        {
            // 如果无法获取文件大小，只显示已下载大小
            if (totalBytesRead % (1024 * 1024) == 0)
            {
                setConsoleColor(COLOR_INFO);
                std::wcout << L"\r已下载: " << (totalBytesRead / 1024 / 1024) << L" MB" << std::flush;
            }
        }
    }

    setConsoleColor(COLOR_NORMAL);
    std::wcout << std::endl; // 换行
    outFile.close();
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // 验证下载的文件是否存在且有效
    if (!isFileExistAndValid(filePath, 1024))
    {
        printError(L"下载的文件检验失败，可能已损坏");
        return false;
    }

    return true;
}

// 执行系统命令并返回错误码
int runSystemCommand(const std::wstring &command, bool showOutput = true)
{
    printInfo(L"执行命令: " + command);

    // 转换为ANSI以使用system函数
    std::string commandAnsi = WideToAnsi(command);

    if (showOutput)
    {
        // 直接执行命令，显示输出
        return system(commandAnsi.c_str());
    }
    else
    {
        // 将输出重定向到NUL，隐藏输出
        std::string redirectedCommand = commandAnsi + " > NUL 2>&1";
        return system(redirectedCommand.c_str());
    }
}

// 创建目录（如果不存在）
bool createDirectoryIfNotExists(const std::wstring &dirPath)
{
    if (!std::filesystem::exists(dirPath))
    {
        std::error_code ec;
        if (!std::filesystem::create_directories(dirPath, ec))
        {
            printError(L"无法创建目录: " + dirPath + L" - " + AnsiToWide(ec.message()));
            return false;
        }
        printInfo(L"创建目录: " + dirPath);
    }
    return true;
}

bool copyFilesFromDirectory(const std::wstring &sourceDir, const std::wstring &destDir, bool showOutput = true)
{
    printInfo(L"正在从 " + sourceDir + L" 复制文件到 " + destDir + L"...");

    // 检查源目录是否存在
    if (!std::filesystem::exists(sourceDir) || !std::filesystem::is_directory(sourceDir))
    {
        printError(L"源目录不存在: " + sourceDir);
        return false;
    }

    // 确保目标目录存在
    if (!createDirectoryIfNotExists(destDir))
    {
        printError(L"无法创建目标目录: " + destDir);
        return false;
    }

    bool success = true;
    std::error_code ec;

    try
    {
        // 遍历源目录中的所有文件和子目录
        for (const auto &entry : std::filesystem::recursive_directory_iterator(sourceDir))
        {
            // 计算源路径相对于sourceDir的相对路径
            std::filesystem::path relPath = std::filesystem::relative(entry.path(), sourceDir);
            // 构建目标路径
            std::filesystem::path destPath = std::filesystem::path(destDir) / relPath;

            if (entry.is_directory())
            {
                // 如果是目录，确保在目标位置创建目录
                std::filesystem::create_directories(destPath, ec);
                if (ec)
                {
                    printWarning(L"无法创建目录: " + destPath.wstring() + L" - " + AnsiToWide(ec.message()));
                    success = false;
                    ec.clear();
                }
            }
            else if (entry.is_regular_file())
            {
                // 如果是文件，复制到目标位置
                // 确保目标目录存在
                std::filesystem::create_directories(destPath.parent_path(), ec);
                if (ec)
                {
                    ec.clear();
                }

                // 复制文件
                std::filesystem::copy_file(
                    entry.path(),
                    destPath,
                    std::filesystem::copy_options::overwrite_existing,
                    ec);

                if (ec)
                {
                    printWarning(L"复制文件失败: " + entry.path().wstring() + L" 到 " + destPath.wstring() + L" - " + AnsiToWide(ec.message()));
                    success = false;
                    ec.clear();
                }
                else
                {
                    if (showOutput)
                    {
                        printInfo(L"已复制: " + relPath.wstring());
                    }
                }
            }
        }
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        printError(L"复制过程中发生错误: " + AnsiToWide(e.what()));
        success = false;
    }

    if (success)
    {
        printSuccess(L"文件复制完成");
    }
    else
    {
        printWarning(L"部分文件复制失败");
    }

    return success;
}

int main()
{
    // 设置控制台编码为 UTF-8
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // 配置std::wcout使用UTF-16输出
    std::locale::global(std::locale(""));
    std::wcout.imbue(std::locale());

    std::wcout << std::endl;
    setConsoleColor(COLOR_SUCCESS);
    std::wcout << L"===== NapCat 安装程序 =====" << std::endl;
    setConsoleColor(COLOR_NORMAL);
    std::wcout << std::endl;

    // 检查QQ安装包
    printInfo(L"检查QQ安装包...");
    if (isFileExistAndValid(QQ_EXE_PATH, 1024 * 1024))
    { // 至少1MB才认为有效
        printSuccess(L"QQ安装包已存在，跳过下载步骤");
    }
    else
    {
        printInfo(L"开始下载QQ...");
        if (!DownloadFile(QQ_DOWNLOAD_URL, QQ_EXE_PATH))
        {
            printError(L"下载QQ失败");
            system("pause");
            return -1;
        }
        printSuccess(L"QQ下载成功");
    }

    printInfo(L"开始解压QQ安装包...");
    // 调用7z解压QQ.exe
    int extractResult = runSystemCommand(L".\\7z.exe -o" + QQ_EXTRACT_DIR + L" x \"" + QQ_EXE_PATH + L"\" -y");
    if (extractResult != 0)
    {
        printError(L"解压QQ失败，错误码: " + std::to_wstring(extractResult));
        system("pause");
        return -1;
    }
    printSuccess(L"QQ解压成功");
    // 移动Files目录下的文件到上级目录
    printInfo(L"正在整理解压后的文件...");
    std::wstring filesDir = QQ_EXTRACT_DIR + L"\\Files";

    // 检查Files目录是否存在
    if (std::filesystem::exists(filesDir) && std::filesystem::is_directory(filesDir))
    {
        // 使用copyFilesFromDirectory复制Files目录下的所有文件和文件夹到上级目录
        bool moveSuccess = copyFilesFromDirectory(filesDir, QQ_EXTRACT_DIR, false);

        if (moveSuccess)
        {
            // 复制成功后删除Files目录
            try
            {
                std::filesystem::remove_all(filesDir);
                printSuccess(L"已成功整理解压后的文件");
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                printWarning(L"删除Files目录失败: " + AnsiToWide(e.what()));
            }
        }
        else
        {
            printError(L"移动Files目录下的文件失败");
        }
    }
    else
    {
        printWarning(L"未找到Files目录，跳过文件整理");
    }

    // 检查NapCat压缩包是否存在
    printInfo(L"检查NapCat压缩包...");
    bool isNapCatExist = isFileExistAndValid(NAPCAT_ZIP_PATH, 10 * 1024); // 至少10KB才认为有效

    if (isNapCatExist)
    {
        printSuccess(L"NapCat压缩包已存在，跳过下载步骤");
    }
    else
    {
        // 使用多个镜像链接尝试下载NapCat
        printInfo(L"开始下载NapCat...");

        std::vector<std::wstring> mirrorUrls = {
            L"https://github.moeyy.xyz/https://github.com/NapNeko/NapCatQQ/releases/latest/download/NapCat.Framework.zip",
            L"https://ghp.ci/https://github.com/NapNeko/NapCatQQ/releases/latest/download/NapCat.Framework.zip",
            L"https://gh.api.99988866.xyz/https://github.com/NapNeko/NapCatQQ/releases/latest/download/NapCat.Framework.zip",
            L"https://github.com/NapNeko/NapCatQQ/releases/latest/download/NapCat.Framework.zip",
        };

        bool isDownloaded = false;
        for (const auto &url : mirrorUrls)
        {
            printInfo(L"尝试从镜像下载: " + url);
            isDownloaded = DownloadFile(url, NAPCAT_ZIP_PATH);
            if (isDownloaded)
            {
                break;
            }
            else
            {
                printWarning(L"该镜像下载失败，尝试下一个...");
            }
        }

        if (!isDownloaded)
        {
            printError(L"下载NapCat失败，所有镜像均不可用");
            system("pause");
            return -1;
        }

        printSuccess(L"NapCat下载成功");
    }

    std::wstring LiteloaderSourceDir = L"./LiteLoader";
    if (!copyFilesFromDirectory(LiteloaderSourceDir, LiteLoader_DIR))
    {
        printWarning(L"从LiteLoader目录复制文件时遇到问题，请检查文件是否完整");
    }

    // 创建解压目录
    if (!createDirectoryIfNotExists(NAPCAT_EXTRACT_DIR))
    {
        printError(L"无法创建NapCat解压目录");
        system("pause");
        return -1;
    }

    printInfo(L"开始解压NapCat...");
    // 调用powershell的 Expand-Archive 解压
    int unzipResult = runSystemCommand(L".\\7z.exe -o" + NAPCAT_EXTRACT_DIR + L" x \"" + NAPCAT_ZIP_PATH + L"\" -y");

    if (unzipResult != 0)
    {
        printError(L"解压NapCat失败，错误码: " + std::to_wstring(unzipResult));
        system("pause");
        return -1;
    }

    // 检查解压后是否成功
    if (!std::filesystem::exists(NAPCAT_EXTRACT_DIR) ||
        !std::filesystem::is_directory(NAPCAT_EXTRACT_DIR))
    {
        printError(L"解压后的目录不存在，可能解压失败");
        system("pause");
        return -1;
    }

    printSuccess(L"NapCat解压成功");

    printInfo(L"正在进行最后的配置...");

    if (!modifyPackageJson())
    {
        printWarning(L"修改package.json失败，可能需要手动修改");
    }
    std::wstring bootmainDir = L"./bootmain";
    if (!copyFilesFromDirectory(bootmainDir, QQ_EXTRACT_DIR))
    {
        printWarning(L"从bootmain目录复制文件时遇到问题，请检查文件是否完整");
    }
    std::wcout << std::endl;
    setConsoleColor(COLOR_SUCCESS);
    std::wcout << L"===== 安装完成 =====" << std::endl;
    std::wcout << L"欢迎使用哦~~ 双击启动即可" << std::endl;
    setConsoleColor(COLOR_NORMAL);

    system("pause");
    return 0;
}