#include "edge.h"
#include <limits.h>
#include <set>
#include <sys/stat.h>
#include "pal/pal_utils.h"
#include "pal/trace.h"
#include "fxr/fx_ver.h"
#include "cpprest/json.h"
#include "deps/deps_format.h"
#include "deps/deps_entry.h"
#include "deps/deps_resolver.h"
#include "fxr/fx_muxer.h"
#include "host/coreclr.h"
#include "host/error_codes.h"

#ifndef EDGE_PLATFORM_WINDOWS
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <fstream>
#include <sstream>
#else
#include <direct.h>
#include <shlwapi.h>
#include <intsafe.h>
#endif

#if EDGE_PLATFORM_APPLE
#include <libproc.h>
#endif

GetFuncFunction getFunc;
CallFuncFunction callFunc;
ContinueTaskFunction continueTask;
FreeHandleFunction freeHandle;
FreeMarshalDataFunction freeMarshalData;
CompileFuncFunction compileFunc;
InitializeFunction initialize;

#define CREATE_DELEGATE(functionName, functionPointer)\
	result = coreclr::create_delegate(\
			host_handle,\
			domain_id,\
			"EdgeJs",\
			"CoreCLREmbedding",\
			functionName,\
			(void**) functionPointer);\
	pal::clr_palstring(functionName, &functionNameString);\
	\
	if (FAILED(result))\
	{\
		throwV8Exception("Call to coreclr_create_delegate() for %s failed with a return code of 0x%x.", functionNameString.c_str(), result);\
		return result;\
	}\
	\
	trace::info(_X("CoreClrEmbedding::Initialize - CoreCLREmbedding.%s() loaded successfully"), functionNameString.c_str());\

pal::string_t GetOSName()
{
#if EDGE_PLATFORM_WINDOWS
	return _X("win");
#elif EDGE_PLATFORM_APPLE
	return _X("osx");
#else
	utsname unameData;

	if (uname(&unameData) == 0)
	{
		return pal::string_t(unameData.sysname);
	}

	// uname() failed, falling back to defaults
	else
	{
		return _X("unix");
	}
#endif
}

pal::string_t GetOSArchitecture()
{
#if defined __X86__ || defined __i386__ || defined i386 || defined _M_IX86 || defined __386__
	return _X("x86");
#elif defined __ia64 || defined _M_IA64 || defined __ia64__ || defined __x86_64__ || defined _M_X64
	return _X("x64");
#elif defined ARM || defined __arm__ || defined _ARM
	return _X("arm");
#endif
}

pal::string_t GetOSVersion()
{
#if EDGE_PLATFORM_WINDOWS
	OSVERSIONINFO version_info;
	ZeroMemory(&version_info, sizeof(OSVERSIONINFO));
	version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

#pragma warning(disable:4996)
	GetVersionEx(&version_info);
#pragma warning(default:4996)

	if (version_info.dwMajorVersion == 6)
	{
		if (version_info.dwMinorVersion == 1)
		{
			return _X("7");
		}

		else if (version_info.dwMinorVersion == 2)
		{
			return _X("8");
		}

		else if (version_info.dwMinorVersion == 3)
		{
			return _X("81");
		}
	}

	else if (version_info.dwMajorVersion == 10 && version_info.dwMinorVersion == 0)
	{
		return _X("10");
	}

	return _X("");
#elif EDGE_PLATFORM_NIX
	utility::ifstream_t lsbRelease;
	lsbRelease.open("/etc/os-release", std::ifstream::in);

	if (lsbRelease.is_open())
	{
		for (utility::string_t line; std::getline(lsbRelease, line); )
		{
			if (line.substr(0, 11) == _X("VERSION_ID="))
			{
				utility::string_t osVersion = line.substr(3);

				if ((osVersion[0] == '"' && osVersion[osVersion.length() - 1] == '"') || ((osVersion[0] == '\'' && osVersion[osVersion.length() - 1] == '\'')))
				{
					osVersion = osVersion.substr(1, osVersion.length() - 2);
				}

				return _X(".") + osVersion;
			}
		}
	}

	return _X("");
#elif EDGE_PLATFORM_APPLE
	utsname unameData;

	if (uname(&unameData) == 0)
	{
		std::string release = unameData.release;
		auto dot_position = release.find(".");

		if (dot_position == std::string::npos)
		{
			return _X("10.0");
		}

		auto version = atoi(release.substr(0, dot_position).c_str());
        pal::stringstream_t versionStringStream;
        versionStringStream << (version - 4);

		return pal::string_t("10.").append(versionStringStream.str());
	}

	else
	{
		return _X("10.0");
	}
#endif
}

std::string get_env_var(std::string const & key) {
	char * val;
	val = getenv(key.c_str());
	std::string retval = "";
	if (val != NULL) {
		retval = val;
	}
	return retval;
}

#if EDGE_PLATFORM_WINDOWS
void AddToTpaList(std::string directoryPath, std::string& tpaList)
{
	const char * const tpaExtensions[] = {
		".ni.dll",
		".dll",
		".ni.exe",
		".exe"
	};

	std::string directoryPathWithFilter(directoryPath);
	directoryPathWithFilter.append("\\*");

	WIN32_FIND_DATA directoryEntry;
	HANDLE fileHandle = FindFirstFile(directoryPathWithFilter.c_str(), &directoryEntry);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return;
	}

	//trace::info(_X("Searching %s for assemblies to add to the TPA list"), directoryPath.c_str());

	std::set<std::string> addedAssemblies;

	// Walk the directory for each extension separately so that we first get files with .ni.dll extension,
	// then files with .dll extension, etc.
	for (int extensionIndex = 0; extensionIndex < sizeof(tpaExtensions) / sizeof(tpaExtensions[0]); extensionIndex++)
	{
		const char* currentExtension = tpaExtensions[extensionIndex];
		size_t currentExtensionLength = strlen(currentExtension);

		// For all entries in the directory
		do
		{
			if ((directoryEntry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
			{
				continue;
			}

			std::string filename(directoryEntry.cFileName);

			// Check if the extension matches the one we are looking for
			size_t extensionPosition = filename.length() - currentExtensionLength;

			if ((extensionPosition <= 0) || (filename.compare(extensionPosition, currentExtensionLength, currentExtension) != 0))
			{
				continue;
			}

			std::string filenameWithoutExtension(filename.substr(0, extensionPosition));

			// Make sure if we have an assembly with multiple extensions present,
			// we insert only one version of it.
			if (addedAssemblies.find(filenameWithoutExtension) == addedAssemblies.end())
			{
				addedAssemblies.insert(filenameWithoutExtension);

				tpaList.append(directoryPath);
				tpaList.append("\\");
				tpaList.append(filename);
				tpaList.append(";");

				//LOG("Added %s to the TPA list", filename.c_str());
			}
		} while (FindNextFile(fileHandle, &directoryEntry));

		FindClose(fileHandle);

		// Rewind the directory stream to be able to iterate over it for the next extension
		fileHandle = FindFirstFile(directoryPathWithFilter.c_str(), &directoryEntry);
	}

	FindClose(fileHandle);
}

char* GetLoadError()
{
	LPVOID message;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message, 0, NULL);

	return (char*)message;
}

HRESULT CoreClrEmbedding::Initialize(BOOL debugMode)
{
	trace::setup();

	pal::string_t edgeDebug;
	pal::getenv(_X("EDGE_DEBUG"), &edgeDebug);

	if (edgeDebug.length() > 0)
	{
		trace::enable();
	}

	trace::info(_X("CoreClrEmbedding::Initialize - 1Started-111"));

	HRESULT result = S_OK;
	pal::string_t functionNameString;


	//
	//variables
	//
	pal::string_t edgeClrDir;
	pal::getenv(_X("N_EDGE_CLR_DIR"), &edgeClrDir);
	std::vector<char> edgeClrDir_cstr;
	pal::pal_clrstring(edgeClrDir, &edgeClrDir_cstr);
	
	std::string tpaList;
	AddToTpaList(edgeClrDir_cstr.data(), tpaList);

	pal::string_t appPath;
	pal::getenv(_X("EDGE_APP_ROOT"), &appPath);

	std::vector<char> appPath_cstr;
	pal::pal_clrstring(appPath, &appPath_cstr);

	const char* useServerGc = "false"; //GetEnvValueBoolean(serverGcVar);      
	const char* globalizationInvariant = "false"; //GetEnvValueBoolean(globalizationInvariantVar);
												  // Build CoreCLR properties
	std::vector<const char*> property_keys = {
		"TRUSTED_PLATFORM_ASSEMBLIES",
		"APP_PATHS",
		"APP_NI_PATHS",
		"NATIVE_DLL_SEARCH_DIRECTORIES",
		"System.GC.Server",
		"System.Globalization.Invariant"
	};

	std::vector<const char*> property_values = {
		// TRUSTED_PLATFORM_ASSEMBLIES
		tpaList.c_str(),
		// APP_PATHS
		appPath_cstr.data(),
		// APP_NI_PATHS
		appPath_cstr.data(),
		// NATIVE_DLL_SEARCH_DIRECTORIES
		appPath_cstr.data(),
		// System.GC.Server
		useServerGc,
		// System.Globalization.Invariant
		globalizationInvariant,
	};

	trace::info(_X("Calling coreclr_initialize()"));
	if (coreclr::bind(edgeClrDir)) {
		trace::info(_X("failed to bind "));
	};
	coreclr::host_handle_t host_handle;
	coreclr::domain_id_t domain_id;

	//N_EDGE_BOOTSTRAPPER_DIR
	pal::string_t bootstrapper_path;
	pal::getenv(_X("N_EDGE_BOOTSTRAPPER_PATH"), &bootstrapper_path);

	std::vector<char> bootstrapperCstr;
	pal::pal_clrstring(bootstrapper_path, &bootstrapperCstr);

	auto hr = coreclr::initialize(
		bootstrapperCstr.data(),
		"Edge",
		&property_keys[0],
		&property_values[0],
		sizeof(property_keys) / sizeof(property_keys[0]),
		&host_handle,
		&domain_id);

	if (!SUCCEEDED(hr))
	{
		trace::error(_X("CoreClrEmbedding::Initialize - Failed to initialize CoreCLR, HRESULT: 0x%X"), hr);
		return StatusCode::CoreClrInitFailure;
	}

	trace::info(_X("CoreCLR initialized successfully"));


	SetCallV8FunctionDelegateFunction setCallV8Function;

	CREATE_DELEGATE("GetFunc", &getFunc);
	CREATE_DELEGATE("CallFunc", &callFunc);
	CREATE_DELEGATE("ContinueTask", &continueTask);
	CREATE_DELEGATE("FreeHandle", &freeHandle);
	CREATE_DELEGATE("FreeMarshalData", &freeMarshalData);
	CREATE_DELEGATE("SetCallV8FunctionDelegate", &setCallV8Function);
	CREATE_DELEGATE("Initialize", &initialize);
	trace::info(_X("Finished creating delegates"));

	trace::info(_X("App domain created successfully (app domain ID: %d)"), domain_id);
	CoreClrGcHandle exception = NULL;

	pal::string_t depsFile = pal::string_t(appPath);
	append_path(&depsFile, _X("NugetTest.deps.json")); // todo this depends on the wrapper app name.

	std::vector<char> depsFile_cstr;
	pal::pal_clrstring(depsFile, &depsFile_cstr);
	
	BootstrapperContext context = { "a","b", depsFile_cstr.data() };

	// call edge delegate
	trace::info(_X("calling c# delegate"));
	initialize(&context, &exception);
	trace::info(_X("end calling c# delegate"));
	if (exception)
	{
		v8::Local<v8::Value> v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
		FreeMarshalData(exception, V8TypeException);

		throwV8Exception(v8Exception);
		return E_FAIL;
	}

	else
	{
		trace::info(_X("CoreClrEmbedding::Initialize - CLR Initialize() function called successfully"));
	}

	exception = NULL;
	setCallV8Function(CoreClrNodejsFunc::Call, &exception);

	if (exception)
	{
		v8::Local<v8::Value> v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
		FreeMarshalData(exception, V8TypeException);

		throwV8Exception(v8Exception);
		return E_FAIL;
	}

	else
	{
		trace::info(_X("CoreClrEmbedding::Initialize - CallV8Function delegate set successfully"));
	}

	trace::info(_X("CoreClrEmbedding::Initialize - Completed"));

	return S_OK;
}
#else
void AddToTpaList(const char* directory, std::string& tpaList){
	const char * const tpaExtensions[] = {
                ".ni.dll",      // Probe for .ni.dll first so that it's preferred if ni and il coexist in the same dir
                ".dll",
                ".ni.exe",
                ".exe",
                };

    DIR* dir = opendir(directory);
    if (dir == nullptr)
    {
        return;
    }

    std::set<std::string> addedAssemblies;

    // Walk the directory for each extension separately so that we first get files with .ni.dll extension,
    // then files with .dll extension, etc.
    for (int extIndex = 0; extIndex < sizeof(tpaExtensions) / sizeof(tpaExtensions[0]); extIndex++)
    {
        const char* ext = tpaExtensions[extIndex];
        int extLength = strlen(ext);

        struct dirent* entry;

        // For all entries in the directory
        while ((entry = readdir(dir)) != nullptr)
        {
            // We are interested in files only
            switch (entry->d_type)
            {
            case DT_REG:
                break;

            // Handle symlinks and file systems that do not support d_type
            case DT_LNK:
            case DT_UNKNOWN:
                {
                    std::string fullFilename;

                    fullFilename.append(directory);
                    fullFilename.append("/");
                    fullFilename.append(entry->d_name);

                    struct stat sb;
                    if (stat(fullFilename.c_str(), &sb) == -1)
                    {
                        continue;
                    }

                    if (!S_ISREG(sb.st_mode))
                    {
                        continue;
                    }
                }
                break;

            default:
                continue;
            }

            std::string filename(entry->d_name);

            // Check if the extension matches the one we are looking for
            int extPos = filename.length() - extLength;
            if ((extPos <= 0) || (filename.compare(extPos, extLength, ext) != 0))
            {
                continue;
            }

            std::string filenameWithoutExt(filename.substr(0, extPos));

            // Make sure if we have an assembly with multiple extensions present,
            // we insert only one version of it.
            if (addedAssemblies.find(filenameWithoutExt) == addedAssemblies.end())
            {
                addedAssemblies.insert(filenameWithoutExt);

                tpaList.append(directory);
                tpaList.append("/");
                tpaList.append(filename);
                tpaList.append(":");
            }
        }
        
        // Rewind the directory stream to be able to iterate over it for the next extension
        rewinddir(dir);
    }
    
    closedir(dir);
}
HRESULT CoreClrEmbedding::Initialize(BOOL debugMode)
{
	trace::setup();

	pal::string_t edgeDebug;
	pal::getenv(_X("EDGE_DEBUG"), &edgeDebug);

	if (edgeDebug.length() > 0)
	{
		trace::enable();
	}

	trace::info(_X("CoreClrEmbedding::Initialize - 1Started-111"));

	HRESULT result = S_OK;
	pal::string_t functionNameString;


	//
	//variables
	//
	pal::string_t edgeClrDir;
	pal::getenv(_X("N_EDGE_CLR_DIR"), &edgeClrDir);
	std::vector<char> edgeClrDir_cstr;
	pal::pal_clrstring(edgeClrDir, &edgeClrDir_cstr);

	std::string tpaList;
	AddToTpaList(edgeClrDir_cstr.data(), tpaList);

	pal::string_t appPath;
	pal::getenv(_X("EDGE_APP_ROOT"), &appPath);

	std::vector<char> appPath_cstr;
	pal::pal_clrstring(appPath, &appPath_cstr);

	const char* useServerGc = "false"; //GetEnvValueBoolean(serverGcVar);      
	const char* globalizationInvariant = "false"; //GetEnvValueBoolean(globalizationInvariantVar);
												  // Build CoreCLR properties
	std::vector<const char*> property_keys = {
		"TRUSTED_PLATFORM_ASSEMBLIES",
		"APP_PATHS",
		"APP_NI_PATHS",
		"NATIVE_DLL_SEARCH_DIRECTORIES",
		"System.GC.Server",
		"System.Globalization.Invariant"
	};

	std::vector<const char*> property_values = {
		// TRUSTED_PLATFORM_ASSEMBLIES
		tpaList.c_str(),
		// APP_PATHS
		appPath_cstr.data(),
		// APP_NI_PATHS
		appPath_cstr.data(),
		// NATIVE_DLL_SEARCH_DIRECTORIES
		appPath_cstr.data(),
		// System.GC.Server
		useServerGc,
		// System.Globalization.Invariant
		globalizationInvariant,
	};

	trace::info(_X("Calling coreclr_initialize()"));
	if (coreclr::bind(edgeClrDir)) {
		trace::info(_X("failed to bind "));
	};
	coreclr::host_handle_t host_handle;
	coreclr::domain_id_t domain_id;

	//N_EDGE_BOOTSTRAPPER_DIR
	pal::string_t bootstrapper_path;
	pal::getenv(_X("N_EDGE_BOOTSTRAPPER_PATH"), &bootstrapper_path);

	std::vector<char> bootstrapperCstr;
	pal::pal_clrstring(bootstrapper_path, &bootstrapperCstr);

	auto hr = coreclr::initialize(
		bootstrapperCstr.data(),
		"Edge",
		&property_keys[0],
		&property_values[0],
		sizeof(property_keys) / sizeof(property_keys[0]),
		&host_handle,
		&domain_id);

	if (!SUCCEEDED(hr))
	{
		trace::error(_X("CoreClrEmbedding::Initialize - Failed to initialize CoreCLR, HRESULT: 0x%X"), hr);
		return StatusCode::CoreClrInitFailure;
	}

	trace::info(_X("CoreCLR initialized successfully"));


	SetCallV8FunctionDelegateFunction setCallV8Function;

	CREATE_DELEGATE("GetFunc", &getFunc);
	CREATE_DELEGATE("CallFunc", &callFunc);
	CREATE_DELEGATE("ContinueTask", &continueTask);
	CREATE_DELEGATE("FreeHandle", &freeHandle);
	CREATE_DELEGATE("FreeMarshalData", &freeMarshalData);
	CREATE_DELEGATE("SetCallV8FunctionDelegate", &setCallV8Function);
	CREATE_DELEGATE("Initialize", &initialize);
	trace::info(_X("Finished creating delegates"));

	trace::info(_X("App domain created successfully (app domain ID: %d)"), domain_id);
	CoreClrGcHandle exception = NULL;

	pal::string_t depsFile = pal::string_t(appPath);
	append_path(&depsFile, _X("NugetTest.deps.json")); // todo this depends on the wrapper app name.

	std::vector<char> depsFile_cstr;
	pal::pal_clrstring(depsFile, &depsFile_cstr);

	BootstrapperContext context = { "a","b", depsFile_cstr.data() };

	// call edge delegate
	trace::info(_X("calling c# delegate"));
	initialize(&context, &exception);
	trace::info(_X("end calling c# delegate"));
	if (exception)
	{
		v8::Local<v8::Value> v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
		FreeMarshalData(exception, V8TypeException);

		throwV8Exception(v8Exception);
		return E_FAIL;
	}

	else
	{
		trace::info(_X("CoreClrEmbedding::Initialize - CLR Initialize() function called successfully"));
	}

	exception = NULL;
	setCallV8Function(CoreClrNodejsFunc::Call, &exception);

	if (exception)
	{
		v8::Local<v8::Value> v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
		FreeMarshalData(exception, V8TypeException);

		throwV8Exception(v8Exception);
		return E_FAIL;
	}

	else
	{
		trace::info(_X("CoreClrEmbedding::Initialize - CallV8Function delegate set successfully"));
	}

	trace::info(_X("CoreClrEmbedding::Initialize - Completed"));

	return S_OK;
}
#endif


CoreClrGcHandle CoreClrEmbedding::GetClrFuncReflectionWrapFunc(const char* assemblyFile, const char* typeName, const char* methodName, v8::Local<v8::Value>* v8Exception)
{
	trace::info(_X("CoreClrEmbedding::GetClrFuncReflectionWrapFunc - Starting"));

	CoreClrGcHandle exception;
	CoreClrGcHandle function = getFunc(assemblyFile, typeName, methodName, &exception);

	if (exception)
	{
		*v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
		FreeMarshalData(exception, V8TypeException);

		return NULL;
	}

	else
	{
		trace::info(_X("CoreClrEmbedding::GetClrFuncReflectionWrapFunc - Finished"));
		return function;
	}
}

void CoreClrEmbedding::CallClrFunc(CoreClrGcHandle functionHandle, void* payload, int payloadType, int* taskState, void** result, int* resultType)
{
	trace::info(_X("CoreClrEmbedding::CallClrFunc"));
	callFunc(functionHandle, payload, payloadType, taskState, result, resultType);
}

void CoreClrEmbedding::ContinueTask(CoreClrGcHandle taskHandle, void* context, TaskCompleteFunction callback, void** exception)
{
	trace::info(_X("CoreClrEmbedding::ContinueTask"));
	continueTask(taskHandle, context, callback, exception);
}

void CoreClrEmbedding::FreeHandle(CoreClrGcHandle handle)
{
	trace::info(_X("CoreClrEmbedding::FreeHandle"));
	freeHandle(handle);
}

void CoreClrEmbedding::FreeMarshalData(void* marshalData, int marshalDataType)
{
	trace::info(_X("CoreClrEmbedding::FreeMarshalData"));
	freeMarshalData(marshalData, marshalDataType);
}

CoreClrGcHandle CoreClrEmbedding::CompileFunc(const void* options, const int payloadType, v8::Local<v8::Value>* v8Exception)
{
    trace::info(_X("CoreClrEmbedding::CompileFunc - Starting"));

    CoreClrGcHandle exception;
    CoreClrGcHandle function = compileFunc(options, payloadType, &exception);

    if (exception)
    {
        *v8Exception = CoreClrFunc::MarshalCLRToV8(exception, V8TypeException);
        FreeMarshalData(exception, V8TypeException);

        return NULL;
    }

    else
    {
        trace::info(_X("CoreClrEmbedding::CompileFunc - Finished"));
        return function;
    }
}
