
namespace Jde
{
	template<class T>
	struct GetAwaitable final : Coroutine::Awaitable<Coroutine::Task<T>>
	{
		GetAwaitable()ι:Awaitable{}
		~GetAwaitable(){ /*DBG("({})AlarmAwaitable::~Awaitable"sv, std::this_thread::get_id());*/ }
	};
}