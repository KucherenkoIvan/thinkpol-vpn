package agent

// undoStack is what was set up so far, each entry undoing one step: run
// undoes them last first.
type undoStack []func()

func (s *undoStack) push(f func()) { *s = append(*s, f) }

// run undoes every step, last first, and empties the stack.
func (s *undoStack) run() {
	for i := len(*s) - 1; i >= 0; i-- {
		(*s)[i]()
	}
	*s = nil
}
