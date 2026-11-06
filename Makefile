.PHONY: demo setup seed backend frontend test eval clean

demo: seed
	@echo "Starting AICTE SmartVerify AI Full System..."
	python backend/main.py

seed:
	@echo "Generating synthetic dataset and ground truth..."
	python data/generator.py

setup:
	@echo "Installing dependencies..."
	python -m pip install -r backend/requirements.txt

test:
	@echo "Running unit and integration tests..."
	pytest backend/tests

eval:
	@echo "Running evaluation harness against ground_truth.json..."
	python eval/harness.py

clean:
	@echo "Cleaning cache files..."
	rm -rf data/seed_output
