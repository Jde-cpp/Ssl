#pragma once
#ifdef JdeSsl_EXPORTS
	#ifdef _MSC_VER 
		#define JDE_SSL_EXPORT __declspec( dllexport )
	#else
		#define JDE_SSL_EXPORT __attribute__((visibility("default")))
	#endif
#else 
	#ifdef _MSC_VER
		#define JDE_SSL_EXPORT __declspec( dllimport )
		#if NDEBUG
			#pragma comment(lib, "Jde.Ssl.lib")
		#else
			#pragma comment(lib, "Jde.Ssl.lib")
		#endif
	#else
		#define JDE_SSL_EXPORT
	#endif
#endif
