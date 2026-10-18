import { Component, type ReactNode } from "react";

/** Keeps a crash in one tool from blanking the whole window. */
export class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="blank">
        <p>This view hit an error and stopped.</p>
        <pre className="code error">{this.state.error.message}</pre>
        <button className="btn" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    );
  }
}
