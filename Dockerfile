# STAGE 1: Builder
# Use openSUSE Leap as the base, then install Python and uv.
FROM opensuse/leap:latest AS builder

# Install Python 3.13, pip, and build dependencies from openSUSE repositories.
RUN zypper -n --gpg-auto-import-keys ref && \
    zypper -n in python313-pip python313-devel gcc && \
    zypper -n clean --all

# Install uv using pip.
RUN python3.13 -m pip install uv

WORKDIR /app

# Copy only the necessary files for dependency installation.
# This improves layer caching, as this step will only re-run if these files change.
COPY pyproject.toml uv.lock ./

# Create a virtual environment and install third-party dependencies into it.
# We use --no-install-project because we will install the project itself in a later step.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv --python /usr/bin/python3.13 && \
    . .venv/bin/activate && \
    uv sync --frozen --no-dev --no-editable --no-install-project

# Now, copy the rest of the application source code.
COPY . .

# Install the project itself into the virtual environment without reinstalling dependencies.
RUN --mount=type=cache,target=/root/.cache/uv \
    . .venv/bin/activate && uv pip install . --no-deps
# STAGE 2: Final Image
FROM opensuse/leap:latest
RUN zypper -n --gpg-auto-import-keys ref && zypper -n in python313 && zypper -n dup && zypper -n clean --all

WORKDIR /app
 
# Copy the virtual environment with all dependencies from the builder stage.
COPY --from=builder /app/.venv /app/.venv

# Set the PATH to include the virtual environment's executables.
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["mcp-server-uyuni"]
