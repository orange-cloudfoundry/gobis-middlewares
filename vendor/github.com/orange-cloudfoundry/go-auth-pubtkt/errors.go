package pubtkt

type ErrNoTicket string

func NewErrNoTicket() error {
	return ErrNoTicket("No ticket found")
}
func (e ErrNoTicket) Error() string {
	return string(e)
}

type ErrNoSSl string

func NewErrNoSSl() error {
	return ErrNoSSl("Request must be secured over https")
}
func (e ErrNoSSl) Error() string {
	return string(e)
}

type ErrSigNotValid string

func NewErrSigNotValid(prevErrors ...error) error {
	if len(prevErrors) == 0 {
		return ErrSigNotValid("Signature not valid.")
	}
	return ErrSigNotValid("Signature not valid: " + prevErrors[0].Error())
}
func (e ErrSigNotValid) Error() string {
	return string(e)
}

type ErrNoValidToken string

func NewErrNoValidToken() error {
	return ErrNoValidToken("Ticket doesn't contains matching token.")
}
func (e ErrNoValidToken) Error() string {
	return string(e)
}

type ErrWrongIp string

func NewErrWrongIp() error {
	return ErrWrongIp("Client ip doesn't match with ip in ticket.")
}
func (e ErrWrongIp) Error() string {
	return string(e)
}

type ErrValidationExpired string

func NewErrValidationExpired() error {
	return ErrValidationExpired("Ticket validation expired.")
}
func (e ErrValidationExpired) Error() string {
	return string(e)
}

type ErrGracePeriodExpired string

func NewErrGracePeriodExpired() error {
	return ErrGracePeriodExpired("Ticket grace period expired.")
}
func (e ErrGracePeriodExpired) Error() string {
	return string(e)
}
