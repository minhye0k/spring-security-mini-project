package mini.project.springsecurity.exception;

public class JwtInvalidException extends RuntimeException {
    public JwtInvalidException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtInvalidException(String message) {
        super(message);
    }
}
