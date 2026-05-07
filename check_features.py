import sys
sys.path.append('/app/src')
try:
    import realtime_extractor
    print(f'SUCCESS: Extracted {len(realtime_extractor.FEATURE_NAMES)} features.')
except Exception as e:
    print(f'FAILED: {e}')
