  success=0
  rounds=10
  for i in $(seq 1 $rounds); do 
    echo "Round $i"
    if npm test; then 
      ((success++))
    else 
      echo "❌ Round $i failed"
    fi
  done
  echo "$success/$rounds passed"
  [ $success -eq $rounds ] && echo "✅ All passed" || echo "❌ Some failed"