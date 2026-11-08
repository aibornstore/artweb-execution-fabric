package cutover

import "fmt"

var ErrAlreadyLocked = fmt.Errorf("cutover state lock already held")

type stateLock struct{ impl platformLock }

func acquireLock(path string) (*stateLock, error) {
	if path == "" {
		return nil, fmt.Errorf("lock path is required")
	}
	impl, err := acquirePlatformLock(path)
	if err != nil {
		return nil, err
	}
	return &stateLock{impl: impl}, nil
}
func (l *stateLock) Close() error {
	if l == nil || l.impl == nil {
		return nil
	}
	err := l.impl.Close()
	l.impl = nil
	return err
}
