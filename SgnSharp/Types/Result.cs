namespace SgnSharp.Types;

/// <summary>
/// Represents the result of an operation that can either succeed or fail
/// Used for railway-oriented programming to avoid exceptions
/// </summary>
public readonly struct Result<T, E>
{
    private readonly T? _value;
    private readonly E? _error;

    private Result(T value)
    {
        _value = value;
        _error = default;
        IsSuccess = true;
    }

    private Result(E error) : this(error, default) { }

    private Result(E error, T? value)
    {
        _value = value;
        _error = error;
        IsSuccess = false;
    }

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    
    public T Value => IsSuccess ? _value! : throw new InvalidOperationException("Cannot access value of failed result");
    public T? ValueOrDefault => _value;
    public E Error => IsFailure ? _error! : throw new InvalidOperationException("Cannot access error of successful result");

    public static Result<T, E> Success(T value) => new(value);
    public static Result<T, E> Failure(E error) => new(error);
    public static Result<T, E> Failure(E error, T? value) => new(error, value);

    public Result<TNew, E> Map<TNew>(Func<T, TNew> func) => 
        IsSuccess ? Result<TNew, E>.Success(func(Value)) : Result<TNew, E>.Failure(Error);

    public Result<T, ENew> MapError<ENew>(Func<E, ENew> func) => 
        IsSuccess ? Result<T, ENew>.Success(Value is T value ? (T)value : default!) : Result<T, ENew>.Failure(func(Error));

    public Result<TNew, E> Bind<TNew>(Func<T, Result<TNew, E>> func) => 
        IsSuccess ? func(Value) : Result<TNew, E>.Failure(Error);

    public Result<T, ENew> BindError<ENew>(Func<E, Result<T, ENew>> func) => 
        IsFailure ? func(Error) : Result<T, ENew>.Success(Value);

    public Result<T, E> OnSuccess(Action<T> action)
    {
        if (IsSuccess) action(Value);
        return this;
    }

    public Result<T, E> OnFailure(Action<E> action)
    {
        if (IsFailure) action(Error);
        return this;
    }

    public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<E, TResult> onFailure) => 
        IsSuccess ? onSuccess(Value) : onFailure(Error);

    public void Match(Action<T> onSuccess, Action<E> onFailure)
    {
        if (IsSuccess) onSuccess(Value);
        else onFailure(Error);
    }

    public Result<T, E> Ensure(Func<T, bool> predicate, E error) => 
        IsFailure || predicate(Value) ? this : Result<T, E>.Failure(error);

    public Result<T, E> Ensure(Func<T, bool> predicate, Func<T, E> errorFactory) => 
        IsFailure || predicate(Value) ? this : Result<T, E>.Failure(errorFactory(Value));

    public static implicit operator Result<T, E>(T value) => Success(value);

    public override string ToString() => 
        IsSuccess ? $"Success: {Value}" : $"Failure: {Error}";
}

// Backward-compatible version with string errors
public readonly struct Result<T>
{
    private readonly Result<T, string> _result;

    private Result(Result<T, string> result) => _result = result;

    public bool IsSuccess => _result.IsSuccess;
    public bool IsFailure => _result.IsFailure;
    public T Value => _result.Value;
    public T? ValueOrDefault => _result.ValueOrDefault;
    public string Error => _result.Error;

    public static Result<T> Success(T value) => new(Result<T, string>.Success(value));
    public static Result<T> Failure(string error) => new(Result<T, string>.Failure(error));
    public static Result<T> Failure(string error, T? value) => new(Result<T, string>.Failure(error, value));

    public Result<TNew> Map<TNew>(Func<T, TNew> func) => 
        new(_result.Map(func));

    public Result<TNew> Bind<TNew>(Func<T, Result<TNew>> func) => 
        new(_result.Bind(v => func(v)._result));

    public Result<T> OnSuccess(Action<T> action)
    {
        _result.OnSuccess(action);
        return this;
    }

    public Result<T> OnFailure(Action<string> action)
    {
        _result.OnFailure(action);
        return this;
    }

    public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<string, TResult> onFailure) => 
        _result.Match(onSuccess, onFailure);

    public static implicit operator Result<T>(T value) => Success(value);
}

/// <summary>
/// Non-generic result for operations that don't return a value
/// </summary>
public readonly struct Result
{
    private readonly string _error;

    private Result(string error)
    {
        _error = error;
        IsSuccess = false;
    }

    private Result(bool success)
    {
        _error = string.Empty;
        IsSuccess = success;
    }

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public string Error => IsFailure ? _error : throw new InvalidOperationException("Cannot access error of successful result");

    public static Result Success() => new(true);
    public static Result Failure(string error) => new(error);

    public Result<T> Map<T>(Func<T> func)
    {
        return IsSuccess ? Result<T>.Success(func()) : Result<T>.Failure(Error);
    }

    public Result<T> Bind<T>(Func<Result<T>> func)
    {
        return IsSuccess ? func() : Result<T>.Failure(Error);
    }

    public Result OnSuccess(Action action)
    {
        if (IsSuccess) action();
        return this;
    }

    public Result OnFailure(Action<string> action)
    {
        if (IsFailure) action(Error);
        return this;
    }

    public TResult Match<TResult>(Func<TResult> onSuccess, Func<string, TResult> onFailure)
    {
        return IsSuccess ? onSuccess() : onFailure(Error);
    }
}